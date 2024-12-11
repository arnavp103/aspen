# Aspen Vpn

Aspen Vpn is a simple VPN setup using wireguard to allow secure access amongst peers in a network. It provides CIDR-based routing, names, and a secure central server to help peers find each other.

## Goals
Specific Targets:
- Allow clients on different routers to connect to each other without needing to expose themselves publicly over the internet
- Allow Peers to be invited to the network using a secure invite system.
- Verify that the connection is secure, so that even if it is MiTM'ed over the internet it cannot be decrypted. 
- Allow Peers to be Named and referred to using said names.


## High-Level System Design

The system consists of two main components:
The Server (Coordinator) serves as the central authority that helps peers find and authenticate each other. Peers will contact the server to:

- Join the network initially
- Get information about other peers they want to connect to
- Register their current network location
- Receive network configuration updates


The Clients (Peers) are the devices that want to communicate. Each client will:

- Maintain a WireGuard interface for secure communication
- Connect to the server to announce their presence
- Connect directly to other peers when needed
- Cache information about known peers

### Server

The backend is a FastAPI server that is connected to a sqlite3 db that's available to all peers. The server will:
- Accept requests from peers to join the network
- Accept requests from peers to get information about other peers
- Accept requests from peers to receive network configuration updates


### Client

The client is just a CLI that makes requests to the backend to:
- Connect and disconnect from the network
- Redeem network invites over an interface using the wg bindings
- Send commands to get or set peers names or CIDR ranges
