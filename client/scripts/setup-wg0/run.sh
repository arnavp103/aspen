# Aspen VPN Client - Setup WireGuard wg0.conf

# Args:
#   $1: Server IP
#   $2: Client Private Key
#   $3: Server Public Key

# Check that the script is being run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Check that we have the correct number of arguments
if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <server_ip> <client_private_key> <server_public_key> <assigned_ip>"
  exit
fi

# Check that wg0.conf.template exists in CWD
# Get CWD
CWD=$(dirname "$0")
if [ ! -f "$CWD/wg0.conf.template" ]; then
  echo "wg0.conf.template not found"
  exit
fi

# Check if /etc/wireguard/wg0.conf already exists
if [ -f /etc/wireguard/wg0.conf ]; then
  read -p "wg0.conf already exists. Overwrite? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit
  fi
fi

server_ip=$1
client_private_key=$2
server_public_key=$3
assigned_ip=$4

# Copy the template to wg0.conf
cp "$CWD/wg0.conf.template" /etc/wireguard/wg0.conf

# Replace the placeholders in wg0.conf
sed -i "s/<SERVER_PUBLIC_IP>/$server_ip/g" /etc/wireguard/wg0.conf
sed -i "s/<YOUR_PRIVATE_KEY>/$client_private_key/g" /etc/wireguard/wg0.conf
sed -i "s/<SERVER_PUBLIC_KEY>/$server_public_key/g" /etc/wireguard/wg0.conf
sed -i "s/<IP_ASSIGNED_BY_SERVER>/$assigned_ip/g" /etc/wireguard/wg0.conf
echo "WireGuard configuration file created at /etc/wireguard/wg0.conf"
