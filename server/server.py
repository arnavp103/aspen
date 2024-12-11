# aspen/server.py
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
from python_wireguard import Server, ClientConnection, Key
from typing import List, Optional
import ipaddress
from functools import wraps

from .database import (
    get_all_peers,
    get_db,
    get_network,
    get_active_peers,
    enable_peer,
    disable_peer,
    get_peer_by_name,
    get_peer_by_ip,
)
from .monitor import WireGuardMonitor

# Global server instance
wg_server: Optional[Server] = None
# Global monitor instance
wg_monitor: Optional[WireGuardMonitor] = None


async def verify_admin(request: Request, db: Session = Depends(get_db)):
    """Verify if the requesting peer is an admin"""
    client_ip = request.client.host
    peer = get_peer_by_ip(db, client_ip)
    if not peer or not peer.is_active or not peer.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return peer


def admin_required(func):
    """Decorator to require admin access"""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = kwargs.get("request")
        db = get_db()
        await verify_admin(request, db)
        return await func(*args, **kwargs)

    return wrapper


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = get_db()
    network = get_network(db)
    if not network:
        raise Exception("No network configuration found")

    # Get the server's VPN IP
    network_addr = ipaddress.ip_network(network.cidr)
    server_ip = str(next(network_addr.hosts()))  # First IP in network

    global wg_server, wg_monitor
    try:
        private_key = Key(network.server_private_key)
        wg_server = Server("wg0", private_key, f"{server_ip}/24", network.listen_port)
        wg_server.enable()

        # Add all active peers
        peers = get_active_peers(db)
        for peer in peers:
            print(f"Adding peer {peer.name} with IP {peer.ip_address} to WireGuard")
            client_key = Key(peer.public_key)
            conn = ClientConnection(client_key, peer.ip_address)
            wg_server.add_client(conn)

        # Start monitoring
        wg_monitor = WireGuardMonitor("wg0")
        await wg_monitor.start()

    except Exception as e:
        print(f"Error setting up WireGuard: {e}")
        if wg_server:
            wg_server.disable()
        if wg_monitor:
            await wg_monitor.stop()
        raise e

    yield

    # Cleanup
    if wg_server:
        wg_server.disable()
    if wg_monitor:
        await wg_monitor.stop()


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def verify_vpn_access(request: Request, call_next):
    """Verify that requests come from VPN IPs"""
    client_ip = request.client.host
    db = get_db()
    network = get_network(db)

    # Check if IP is in VPN range
    try:
        client_addr = ipaddress.ip_address(client_ip)
        network_addr = ipaddress.ip_network(network.cidr)
        if client_addr not in network_addr:
            raise HTTPException(
                status_code=403, detail="Access only allowed through VPN"
            )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    response = await call_next(request)
    return response


class PeerStatus(BaseModel):
    name: str
    ip_address: str
    is_active: bool
    is_admin: bool
    last_handshake: Optional[datetime]
    last_endpoint: Optional[str]
    is_online: bool  # Determined by recent handshake

    class Config:
        # map Pydantic model from SQLAlchemy model
        from_attributes = True


def is_peer_online(last_handshake: Optional[datetime]) -> bool:
    """Consider peer online if handshake was within last 3 minutes"""
    if not last_handshake:
        return False
    now = datetime.now(timezone.utc)
    if last_handshake.tzinfo is None:  # Make naive datetime aware
        last_handshake = last_handshake.replace(tzinfo=timezone.utc)
    return (now - last_handshake).total_seconds() < 180  # 3 minutes


@app.get("/peers/status", response_model=List[PeerStatus])
@admin_required
async def get_peer_status(request: Request, db: Session = Depends(get_db)):
    """Get status of all peers (admin only)"""
    peers = get_all_peers(db)
    return [
        PeerStatus(
            name=peer.name,
            ip_address=peer.ip_address,
            is_active=peer.is_active,
            is_admin=peer.is_admin,
            last_handshake=peer.last_handshake,
            last_endpoint=peer.last_endpoint,
            is_online=is_peer_online(peer.last_handshake),
        )
        for peer in peers
    ]


@app.get("/peers")
async def list_peers(request: Request, db: Session = Depends(get_db)):
    """List all peers"""
    peers = get_all_peers(db)
    return [
        {
            "name": p.name,
            "ip": p.ip_address,
            "online": is_peer_online(p.last_handshake),
            "last_handshake": p.last_handshake,
        }
        for p in peers
    ]


@app.post("/peers/{name}/enable")
@admin_required
async def enable_peer_endpoint(
    name: str, request: Request, db: Session = Depends(get_db)
):
    """Enable a peer (admin only)"""
    if enable_peer(db, name):
        peer = get_peer_by_name(db, name)
        if peer and wg_server:
            try:
                client_key = Key(peer.public_key)
                conn = ClientConnection(client_key, peer.ip_address)
                wg_server.add_client(conn)
                return {"status": "enabled"}
            except Exception as e:
                # Rollback peer activation if WireGuard update fails
                disable_peer(db, name)
                raise HTTPException(
                    status_code=500, detail=f"Failed to update WireGuard: {str(e)}"
                )
    raise HTTPException(status_code=404, detail="Peer not found")


@app.post("/peers/{name}/disable")
@admin_required
async def disable_peer_endpoint(
    name: str, request: Request, db: Session = Depends(get_db)
):
    """Disable a peer (admin only)"""
    if disable_peer(db, name):
        peer = get_peer_by_name(db, name)
        if peer and wg_server:
            try:
                # Rebuild WireGuard configuration without this peer
                active_peers = get_active_peers(db)
                for active_peer in active_peers:
                    if active_peer.name != name:
                        client_key = Key(active_peer.public_key)
                        conn = ClientConnection(client_key, active_peer.ip_address)
                        wg_server.add_client(conn)
                return {"status": "disabled"}
            except Exception as e:
                # Rollback peer deactivation if WireGuard update fails
                enable_peer(db, name)
                raise HTTPException(
                    status_code=500, detail=f"Failed to update WireGuard: {str(e)}"
                )
    raise HTTPException(status_code=404, detail="Peer not found")


@app.get("/status")
async def get_status(request: Request, db: Session = Depends(get_db)):
    """Get server status (available to all VPN peers)"""
    network = get_network(db)
    requesting_peer = get_peer_by_ip(db, request.client.host)
    return {
        "network_name": network.name if network else None,
        "is_running": wg_server is not None,
        "active_peers": len(get_active_peers(db)) if network else 0,
        "your_name": requesting_peer.name if requesting_peer else None,
        "admin_rights": requesting_peer.is_admin if requesting_peer else False,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
