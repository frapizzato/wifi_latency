#!/bin/bash
# Cleanup script for dual-interface monitoring

set -e

MONITOR_PHY="wlxe84e06b0d13b"
MONITOR_IF="mon0"

echo "=========================================="
echo "Dual Interface Monitor Cleanup"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "Removing monitor interface $MONITOR_IF..."
iw dev $MONITOR_IF del 2>/dev/null || true

echo "Bringing $MONITOR_PHY back to managed mode..."
ip link set $MONITOR_PHY down 2>/dev/null || true
ip link set $MONITOR_PHY up 2>/dev/null || true

echo ""
echo "✓ Cleanup complete!"
echo "Both interfaces restored to normal operation."
