"""Database models and functions for the server"""

from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
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
