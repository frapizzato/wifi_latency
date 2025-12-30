#!/bin/bash

# Setup script to create a persistent monitor interface
# Usage: sudo ./setup_monitor.sh [interface] [mon_interface]
# Example: sudo ./setup_monitor.sh wlxe84e06b0d13b mon0

set -e

MAIN_IFACE="${1}"
MON_IFACE="${2}"

echo "Setting up monitor interface..."
echo "Main interface: $MAIN_IFACE"
echo "Monitor interface: $MON_IFACE"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Bring down main interface
echo "Bringing down $MAIN_IFACE..."
   ip link set $MAIN_IFACE down
sleep 1

# Create virtual monitor interface
echo "Creating virtual monitor interface $MON_IFACE..."
iw $MAIN_IFACE interface add $MON_IFACE type monitor flags control
sleep 1

# Bring up main interface
echo "Bringing up $MAIN_IFACE..."
ip link set $MAIN_IFACE up
sleep 1

# Bring up monitor interface
echo "Bringing up $MON_IFACE..."
ip link set $MON_IFACE up
sleep 2

# Verify
echo ""
echo "Monitor interface setup complete!"
echo ""
iw dev | grep -A 5 $MON_IFACE
echo ""
echo "Monitor interface is ready. You can now use it with:"
echo "sudo ./ping_ack_latency -i $MON_IFACE -g 192.168.0.1"
