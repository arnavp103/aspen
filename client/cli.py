
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
from time import sleep




@click.group()
def cli():
    """Aspen VPN client sided tool"""
    pass


def _up():
    """Start the VPN server"""
    subprocess.run(["sudo", "wg-quick", "up", "wg0"])

def _down():
    """Stop the VPN server"""
    subprocess.run(["sudo", "wg-quick", "down", "wg0"])


@cli.command()
def up():
    """Start the wireguard VPN server"""
    _up()

@cli.command()
def down():
    """Stop the wireguard VPN server"""
    _down()


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

def _add_host(ip: str, alias: str):
    """Add a host to the /etc/hosts file"""
    file_path = os.path.join(cwd, "client/scripts/hosts/add-host.sh")
    subprocess.run(["sudo", "bash", file_path, ip, alias])

def _remove_host(alias: str):
    """Remove a host from the /etc/hosts file"""
    file_path = os.path.join(cwd, "client/scripts/hosts/remove-host.sh")
    subprocess.run(["sudo", "bash", file_path, alias])

@cli.command()
@click.argument("ip", type=str)
@click.argument("alias", type=str)
def add_host(ip: str, alias: str):
    """Add a host to the /etc/hosts file"""
    _add_host(ip, alias)
   
@cli.command()
@click.argument("alias", type=str)
def remove_host(alias: str):
    """Remove a host from the /etc/hosts file"""
    _remove_host(alias)

def _send_key(server_ip: str, pkey: str):
    """Send the public key to the server.
        Requires either file or pkey content to be provided.
        Priority is given to pkey content.
        """
    
    public_key = pkey
    print("Sending to server\n")
    url = f"http://{server_ip}:8000/invitations/redeem"
    data = {"public_key": str(public_key)}
    response = requests.post(url, json=data)
    if response.status_code == 200:
        click.echo("Public key sent successfully")
    else:
        click.echo("Failed to send public key")
    
    return response

@cli.command()
@click.argument("server_ip", type=str)
@click.option("--pkey", help="Private key text", type=str)
@require_wg_running
def send_key(server_ip: str, pkey: str):
    """Send the public key to the server.
        Requires either file or pkey content to be provided.
        Priority is given to pkey content.
        """
    return _send_key(server_ip, pkey)


def _make_wg_config(ip: str, clientpk: str, serverpk: str, assigned_ip: str):
    print("Making wg config")
    print(ip)
    print(clientpk)
    print(serverpk)
    print(assigned_ip)
    file_path = os.path.join(cwd, "client/scripts/setup-wg0/run.sh")
    subprocess.run(["sudo", "bash", file_path, ip, clientpk, serverpk, assigned_ip])

@cli.command()
@click.argument("ip", type=str)
@click.argument("clientpk", type=str)
@click.argument("serverpk", type=str)
@click.argument("assigned_ip", type=str)
def make_wg_config(ip: str, clientpk: str, serverpk: str):
    """
    Generate a WireGuard configuration file.\n
    make-wg-config <IP> <CLIENTPK> <SERVERPK>\n
    IP: IP address of the server\n
    CLIENTPK: Public key of the client\n
    SERVERPK: Public key of the server\n
    """
    _make_wg_config(ip, clientpk, serverpk)


def _generate_key(no_save: bool):
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
@click.option("--no-save", is_flag=True, help="Don't save the keys to a file")
def generate_key(no_save: bool):
    """Start the VPN server"""
    return _generate_key(no_save)

def _teardown():
    """Remove the VPN server"""
    subprocess.run(["sudo", "wg-quick", "down", "wg0"])
    subprocess.run(["sudo", "rm", "/etc/wireguard/wg0.conf"])

@cli.command()
def teardown():
    """Remove the VPN server"""
    _teardown()

@cli.command()
@click.option("--ip", help="IP address of the server", type=str, default="10.42.0.1")
@click.option("--no-add", is_flag=True, help="Don't add the peer to the /etc/hosts file")
@require_wg_running
def list(ip: str, no_add: bool):
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
        click.echo(f"Name: aspn.{peer['name']} (ip={peer['ip']})   Online: {peer['online']}    Last Handshake: {peer['last_handshake']}")
        click.echo()

        if not no_add:
            add_host(peer["ip"], f"aspn.{peer['name']}")

@cli.command()
@click.argument("invite_file", type=str)
@click.option("--ip", help="IP address of the server", type=str, default="10.42.0.1")
def register(invite_file: str, ip: str):
    """Register the client with the server given the invitation file"""

    with open(invite_file, "r") as f:
        invite = json.load(f)
        print(invite)
        server_ip = str(ip)
        real_server_public_key = invite["server"]["public_key"]
        # server_public_key = invite["server_public_key"]
        client_private_key = invite["temp_private_key"]
        assigned_ip = invite["ip_address"]

        # Establish a temporary connection to the server
        _make_wg_config(server_ip, client_private_key, real_server_public_key, assigned_ip); #server_public_key)
        _up()
        sleep(0.5)
        private_key, public_key = _generate_key(no_save=True)

        # Send the public key to the server
        response = _send_key(server_ip, public_key)
        if response.status_code != 200:
            click.echo(response.text)

            _teardown()
            return
        
        _teardown()
        sleep(0.5)

        # Establish a permanent connection to the server
        _make_wg_config(server_ip, private_key, real_server_public_key, assigned_ip)
        sleep(0.5)
        _up()
        sleep(0.5)

        # Test ping the server and check if it's successful
        client = Client(private_key, server_ip)
        response = asyncio.run(client.ping())

        if response:
            click.echo("Client successfully registered")
        else:
            click.echo("Failed to register client")
        
if __name__ == "__main__":
    cli()
