# Aspen VPN - Add Host

# Modify /etc/hosts file

# Check if the user is root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# $1 is the IP address
# $2 is the Alias

# Check if the IP address and Alias are provided
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: add-host.sh <IP Address> <Alias>"
  exit
fi

# Check if an entry with the IP address and EXACT Alias exists
if ! grep -q "^$1[[:space:]]\+$2$" /etc/hosts; then
    echo "Host does not exist"
    exit
fi

# Remove the host (EXACT ALIAS)
sed -i "/^$1[[:space:]]\+$2$/d" /etc/hosts

# If there are no more hosts under the Aspen VPN Hosts section, remove the section
if ! grep -q "^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+[[:space:]]\+[a-zA-Z0-9\-]\+$" /etc/hosts; then
    sed -i "/^#### Aspen VPN Hosts ####$/d" /etc/hosts
fi

echo "Host removed successfully"