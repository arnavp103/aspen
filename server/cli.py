# aspen/cli.py
import click
import ipaddress
from python_wireguard import Key
import uvicorn
from .database import init_db, get_db, get_network, create_network, add_peer
from .server import app


@click.group()
def cli():
    """Aspen VPN server management tool"""
    init_db()


@cli.command()
def new():
    """Create a new network configuration"""
    db = get_db()
    existing_network = get_network(db)
    if existing_network:
        click.echo(f"Network already exists: {existing_network.name}")
        click.echo(f"CIDR: {existing_network.cidr}")
        click.echo(f"Listen port: {existing_network.listen_port}")
        click.echo(f"External endpoint: {existing_network.external_endpoint or 'auto'}")
        return

    name = click.prompt("Network name", type=str)

    while True:
        cidr = click.prompt("Network CIDR", default="10.42.0.0/16")
        try:
            network = ipaddress.ip_network(cidr)
            if network.num_addresses < 256:  # Ensure enough addresses
                click.echo("Network too small. Please use a larger CIDR range.")
                continue
            break
        except ValueError:
            click.echo("Invalid CIDR format. Please try again.")

    external_endpoint = click.prompt(
        "External endpoint (press Enter for auto)", default="", show_default=False
    )
    listen_port = click.prompt("Listen port", default=51820, type=int)

    # Generate server keys
    private, public = Key.key_pair()

    network = create_network(
        db=db,
        name=name,
        cidr=cidr,
        listen_port=listen_port,
        external_endpoint=external_endpoint if external_endpoint else None,
        server_private_key=str(private),
        server_public_key=str(public),
    )

    click.echo(f"\nNetwork {network.name} created successfully")
    click.echo(f"Server public key: {network.server_public_key}")
    click.echo(f"Next step: Add peers using 'aspen add-peer'")


@cli.command()
@click.option("--admin", is_flag=True, help="Make the peer an admin")
def create_peer(admin: bool):
    """Add a new peer to the network"""
    db = get_db()
    network = get_network(db)

    if not network:
        click.echo("No network configured. Run 'aspen new' first.")
        return

    # Get peer name
    name = click.prompt("Name", type=str)

    # Generate a suggested IP from the network CIDR
    network_addr = ipaddress.ip_network(network.cidr)
    server_ip = next(network_addr.hosts())  # First IP reserved for server
    suggested_ip = str(next(network_addr.hosts()))  # Second IP for first peer

    ip_address = click.prompt("IP address", default=suggested_ip)
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip == server_ip:
            click.echo("Error: This IP is reserved for the server")
            return
        if ip not in network_addr:
            click.echo("Error: IP not in network range")
            return
    except ValueError:
        click.echo("Invalid IP address format")
        return

    # Get the peer's public key
    public_key = click.prompt("Public key")
    try:
        Key(public_key)
    except:
        click.echo("Invalid public key format")
        return

    peer = add_peer(db, name, ip_address, public_key, is_admin=admin)
    click.echo(f"\nPeer {peer.name} added successfully")
    click.echo(f"IP Address: {peer.ip_address}")
    if admin:
        click.echo("Admin privileges granted")


@cli.command()
def serve():
    """Start the VPN server"""
    db = get_db()
    network = get_network(db)

    if not network:
        click.echo("No network configured. Run 'aspen new' first.")
        return

    # Get server IP from network CIDR
    network_addr = ipaddress.ip_network(network.cidr)
    server_ip = str(next(network_addr.hosts()))

    click.echo(f"Starting Aspen VPN server for network: {network.name}")
    click.echo(f"Network CIDR: {network.cidr}")
    click.echo(f"Server IP: {server_ip}")
    click.echo(f"WireGuard port: {network.listen_port}")
    click.echo(f"Management API: {server_ip}:8000 (only accessible through VPN)\n")

    try:
        # Start FastAPI on the VPN interface
        uvicorn.run(app, host=server_ip, port=8000)
    except Exception as e:
        click.echo(f"Error starting server: {e}")


if __name__ == "__main__":
    cli()
