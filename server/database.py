"""Database models and functions for the server"""

from sqlalchemy import DateTime, create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import uuid

from typing import Optional

from datetime import datetime, timezone
import os

Base = declarative_base()


class Network(Base):
    __tablename__ = "network"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    cidr = Column(String)
    listen_port = Column(Integer)
    external_endpoint = Column(String, nullable=True)
    server_private_key = Column(String)
    server_public_key = Column(String)


class Peer(Base):
    __tablename__ = "peers"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    ip_address = Column(String, unique=True)
    public_key = Column(String, unique=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    last_handshake = Column(DateTime, nullable=True)
    last_endpoint = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=str(datetime.now(timezone.utc)))


class Invitation(Base):
    __tablename__ = "invitations"
    
    id = Column(Integer, primary_key=True)
    token = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=True)
    temp_private_key = Column(String, nullable=False)  # Store temporarily
    temp_public_key = Column(String, nullable=False)
    assigned_ip = Column(String, unique=True, nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=str(datetime.now(timezone.utc)))
    is_used = Column(Boolean, default=False)

# DATABASE_PATH = os.path.expanduser("~/.local/share/simplevpn/")
# os.makedirs(DATABASE_PATH, exist_ok=True)
DATABASE_PATH = os.path.expanduser(".")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}/vpn.db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        return db
    finally:
        db.close()


def get_network(db):
    """Get the network configuration if it exists"""
    return db.query(Network).first()


def create_network(
    db,
    name: str,
    cidr: str,
    listen_port: int,
    external_endpoint: str,
    server_private_key: str,
    server_public_key: str,
):
    """Create a new network configuration"""
    network = Network(
        name=name,
        cidr=cidr,
        listen_port=listen_port,
        external_endpoint=external_endpoint,
        server_private_key=server_private_key,
        server_public_key=server_public_key,
    )
    db.add(network)
    db.commit()
    return network


def verify_admin(db, public_key: str) -> bool:
    """Verify if a peer is an admin"""
    peer = (
        db.query(Peer)
        .filter_by(public_key=public_key, is_active=True, is_admin=True)
        .first()
    )
    return peer is not None


def add_peer(db, name: str, ip_address: str, public_key: str, is_admin: bool = False):
    """Add a new peer"""
    peer = Peer(
        name=name, ip_address=ip_address, public_key=public_key, is_admin=is_admin
    )
    db.add(peer)
    db.commit()
    return peer


def enable_peer(db, name: str) -> bool:
    """Enable a peer by name"""
    peer = db.query(Peer).filter_by(name=name).first()
    if peer:
        peer.is_active = True
        db.commit()
        return True
    return False


def disable_peer(db, name: str) -> bool:
    """Disable a peer by name"""
    peer = db.query(Peer).filter_by(name=name).first()
    if peer:
        peer.is_active = False
        db.commit()
        return True
    return False


def get_active_peers(db):
    """Get all active peers"""
    return db.query(Peer).filter_by(is_active=True).all()


def get_peer_by_name(db, name: str):
    """Get a peer by name"""
    return db.query(Peer).filter_by(name=name).first()


def get_peer_by_ip(db, ip_address: str):
    """Get a peer by IP address"""
    return db.query(Peer).filter_by(ip_address=ip_address).first()


def update_peer_status(
    db, public_key: str, handshake_time: datetime, endpoint: str = None
):
    """Update given public key's peer's last handshake time and endpoint"""
    peer = db.query(Peer).filter_by(public_key=public_key).first()
    if peer:
        peer.last_handshake = handshake_time
        if endpoint:
            peer.last_endpoint = endpoint
        db.commit()
        return True
    return False


def get_all_peers(db):
    """Get all peers with their status"""
    return db.query(Peer).all()


def create_invitation(db, name: str, assigned_ip: str, is_admin: bool = False) -> dict:
    """Create a new invitation"""
    from python_wireguard import Key, ClientConnection  # Import here to avoid circular imports
    from .server import wg_server  # Import here to avoid circular imports
    
    # Generate temporary keypair
    private, public = Key.key_pair()
    
    # Generate unique token
    token = str(uuid.uuid4())
    
    invitation = Invitation(
        token=token,
        name=name,
        temp_private_key=str(private),
        temp_public_key=str(public),
        assigned_ip=assigned_ip,
        is_admin=is_admin,
    )

    # Add to WireGuard server
    if wg_server:
        client_key = Key(str(public))
        conn = ClientConnection(client_key, assigned_ip)
        wg_server.add_client(conn)
    else:
        raise Exception("WireGuard server not initialized for invitation creation. Try serving the application first with aspen-server serve")
    
    db.add(invitation)
    db.commit()
    
    # Return data needed for invitation file
    return {
        'name': name,
        'temp_private_key': str(private),
        'server_public_key': get_network(db).server_public_key,
        'assigned_ip': assigned_ip
    }

def get_invitation(db, token: str) -> Optional[Invitation]:
    """Get an invitation by token"""
    return db.query(Invitation).filter_by(token=token, is_used=False).first()

def mark_invitation_used(db, token: str) -> bool:
    """Mark an invitation as used"""
    invitation = get_invitation(db, token)
    if invitation and not invitation.is_used:
        invitation.is_used = True
        db.commit()
        return True
    return False

# Add to existing methods
def get_pending_invitations(db):
    """Get all unused invitations"""
    return db.query(Invitation).filter_by(is_used=False).all()