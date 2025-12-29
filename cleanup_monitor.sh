#!/bin/bash

# Cleanup script to remove monitor interface
# Usage: sudo ./cleanup_monitor.sh [mon_interface] [main_interface]
# Example: sudo ./cleanup_monitor.sh mon0 wlxe84e06b0d13b

set -e

MON_IFACE="${1}"
MAIN_IFACE="${2}"

echo "Cleaning up monitor interface..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Bring down monitor interface
echo "Bringing down $MON_IFACE..."
ip link set $MON_IFACE down 2>/dev/null || true
sleep 1

# Delete monitor interface
echo "Deleting $MON_IFACE..."
iw $MON_IFACE del 2>/dev/null || true
sleep 1

# Bring up main interface
echo "Bringing up $MAIN_IFACE..."
ip link set $MAIN_IFACE up 2>/dev/null || true
sleep 1

echo "Cleanup complete!"
