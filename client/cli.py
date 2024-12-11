
import argparse
import requests
import asyncio
from python_wireguard import Client, Key, ServerConnection
import subprocess

private, public = Key.key_pair()
# aspen/cli.py
import click
import ipaddress
import json
from python_wireguard import Key
import os
cwd = os.getcwd()
import functools

@click.group()
def cli():
    """Aspen VPN client sided tool"""
    pass

@cli.command()
def up():
    """Start the wireguard VPN server"""
    subprocess.run(["sudo", "wg-quick", "up", "wg0"])

@cli.command()
def down():
    """Stop the wireguard VPN server"""
    subprocess.run(["sudo", "wg-quick", "down", "wg0"])


def require_wg_running(func):
    """
    Decorator to check if WireGuard is running
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        response = subprocess.run(["sudo", "wg", "show", "wg0"], capture_output=True)
        if not response.returncode == 0:
            click.echo("WireGuard is not running")
            exit(1)
        return func(*args, **kwargs)
    return wrapper

@cli.command()
@click.argument("server_ip", type=str)
@click.option("--file", help="Path to keys.pkl [default: ./keys.pkl]", type=str, default="keys.pkl")
@click.option("--pkey", help="Private key text", type=str)
@require_wg_running
def send_key(server_ip: str, file: str, pkey: str):
    """Send the public key to the server.
        Requires either file or pkey content to be provided.
        Priority is given to pkey content.
        """
    
    public_key = pkey
    if not public_key:
        with open(file, "rb") as f:
            _, public = pickle.load(f)
            public_key = public

    url = f"http://{server_ip}:8000/register"
    data = {"public_key": public_key}
    response = requests.post(url, json=data)
    if response.status_code == 200:
        click.echo("Public key sent successfully")
    else:
        click.echo("Failed to send public key")
    
    return response

@cli.command()
@click.argument("ip", type=str)
@click.argument("clientpk", type=str)
@click.argument("serverpk", type=str)
def make_wg_config(ip: str, clientpk: str, serverpk: str):
    """
    Generate a WireGuard configuration file.\n
    make-wg-config <IP> <CLIENTPK> <SERVERPK>\n
    IP: IP address of the server\n
    CLIENTPK: Public key of the client\n
    SERVERPK: Public key of the server\n
    """
    file_path = os.path.join(cwd, "client/scripts/setup-wg0/run.sh")
    subprocess.run(["sudo", "bash", file_path, ip, clientpk, serverpk])

@cli.command()
@click.option("--no-save", is_flag=True, help="Don't save the keys to a file")
def generate_key(no_save: bool):
    """Start the VPN server"""
    private, public = Key.key_pair()
    click.echo(f"Private key: {private}")
    click.echo(f"Public key: {public}")

    # Save into a file
    if not no_save:
        with open("keys.pkl", "wb") as f:
            pickle.dump((str(private), str(public)), f)

    return private, public

@cli.command()
def teardown():
    """Remove the VPN server"""
    subprocess.run(["sudo", "wg-quick", "down", "wg0"])
    subprocess.run(["sudo", "rm", "/etc/wireguard/wg0.conf"])


@cli.command()
@click.option("--ip", help="IP address of the server", type=str, default="10.0.0.1")
@require_wg_running
def list(ip: str):
    """List all the peers in the network"""

    # Get the list of peers
    url = f"http://{ip}:8000/peers"
    response = requests.get(url)

    if response.status_code != 200:
        click.echo("Failed to get the list of peers")
        return
    
    click.echo("List of peers")
    peers = response.json()
    for peer in peers:
        click.echo(f"Name: {peer['name']} (ip={peer['ip']})   Online: {peer['online']}    Last Handshake: {peer['last_handshake']}")
        click.echo()

@cli.command()
@click.argument("invite_file", type=str)
def register(invite_file: str):
    """Register the client with the server given the invitation file"""

    with open(invite_file, "rb") as f:
        invite = json.loads(f)

        server_ip = invite["ip_address"]
        real_server_public_key = invite.server["public_key"]
        server_public_key = invite["server_public_key"]
        client_private_key = invite["client_private_key"]

        # Establish a temporary connection to the server
        make_wg_config(server_ip, client_private_key, server_public_key)
        up()

        private_key, public_key = generate_key(no_save=True)

        # Send the public key to the server
        response = send_key(server_ip, public_key)
        if response.status_code != 200:
            click.echo("Failed to send public key.")
            click.echo(response.text)

            teardown()
            return
        
        # Establish a permanent connection to the server
        make_wg_config(server_ip, private_key, real_server_public_key)
        up()

        # Test ping the server and check if it's successful
        client = Client(private_key, server_ip)
        response = asyncio.run(client.ping())

        if response:
            click.echo("Client successfully registered")
        else:
            click.echo("Failed to register client")
        
if __name__ == "__main__":
    cli()
