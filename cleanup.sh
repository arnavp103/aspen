#!/bin/bash

# Function to check if interface exists and remove it
remove_interface() {
    if ip link show $1 &>/dev/null; then
        echo "Removing interface $1..."
        sudo ip link delete $1
    else
        echo "Interface $1 does not exist"
    fi
}

# Remove both server and client interfaces
remove_interface "wg0"
remove_interface "wg1"
remove_interface "VPN"

# Optionally, kill any running server processes
sudo pkill -f "python server/main.py"

echo "Cleanup complete!"