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

# Check if the IP address is valid
if ! [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid IP address"
  exit
fi

# Look for - #### Aspen VPN Hosts #### in /etc/hosts
# If it doesn't exist, add it

if ! grep -q "#### Aspen VPN Hosts ####" /etc/hosts; then
  echo "#### Aspen VPN Hosts ####" >> /etc/hosts
fi

# Check if the host already exists (exact match)
if grep -q "^$1[[:space:]]\+$2$" /etc/hosts; then
    echo "Host already exists"
    exit
fi

# Add the host under the Aspen VPN Hosts section
echo "$1 $2" >> /etc/hosts

echo "Host added successfully"