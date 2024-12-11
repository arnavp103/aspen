# aspen/monitor.py
import asyncio
from datetime import datetime
import subprocess
from typing import Optional, Dict
from .database import get_db, update_peer_status


class WireGuardMonitor:
    def __init__(self, interface: str = "wg0"):
        self.interface = interface
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the monitoring task"""
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self):
        """Stop the monitoring task"""
        self._running = False
        if self._task:
            try:
                self._task.cancel()
                await self._task
            except asyncio.CancelledError:
                pass

    def _get_wireguard_status(self) -> Dict:
        """Get current WireGuard interface status"""
        try:
            result = subprocess.run(
                ["sudo", "wg", "show", self.interface, "dump"],
                capture_output=True,
                text=True,
                check=True,
            )

            # Parse the dump output
            # Format: <public-key> <preshared-key> <endpoint> <allowed-ips> <latest-handshake> <transfer-rx> <transfer-tx> <persistent-keepalive>
            peers = {}
            for line in result.stdout.strip().split("\n")[
                1:
            ]:  # Skip first line (interface)
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) >= 5:
                    public_key = parts[0]
                    endpoint = parts[2] if parts[2] else None
                    latest_handshake = int(parts[4]) if parts[4] else 0

                    curr_tz = datetime.now().astimezone().tzinfo

                    peers[public_key] = {
                        "endpoint": endpoint,
                        "last_handshake": datetime.fromtimestamp(
                            latest_handshake, curr_tz
                        )
                        if latest_handshake > 0
                        else None,
                    }
            return peers
        except subprocess.CalledProcessError:
            return {}

    async def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                peers = self._get_wireguard_status()
                if peers:
                    db = get_db()
                    for public_key, status in peers.items():
                        if status["last_handshake"]:
                            update_peer_status(
                                db,
                                public_key,
                                status["last_handshake"],
                                status["endpoint"],
                            )
            except Exception as e:
                print(f"Error in monitor loop: {e}")

            await asyncio.sleep(10)  # Check every 10 seconds
