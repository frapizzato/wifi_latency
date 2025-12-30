#!/bin/bash
# Setup script for dual-interface monitoring
# Managed interface: wlp0s20f3 (for traffic)
# Monitor interface: wlxe84e06b0d13b (for capture)

set -e

MANAGED_IF="wlp0s20f3"
MONITOR_PHY="wlxe84e06b0d13b"
MONITOR_IF="mon0"

echo "=========================================="
echo "Dual Interface Monitor Setup"
echo "=========================================="
echo "Managed interface: $MANAGED_IF"
echo "Monitor adapter:   $MONITOR_PHY"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Get channel and bandwidth from managed interface
echo "[1/5] Detecting channel and bandwidth from $MANAGED_IF..."
CHANNEL=$(iw dev $MANAGED_IF info | grep channel | awk '{print $2}')
WIDTH=$(iw dev $MANAGED_IF info | grep channel | grep -oP 'width: \K[0-9]+' || echo "20")
if [ -z "$CHANNEL" ]; then
    echo "Error: Could not detect channel. Is $MANAGED_IF connected?"
    echo "You can manually specify channel: sudo iw dev $MONITOR_IF set channel <num>"
    exit 1
fi
echo "      Channel: $CHANNEL"
echo "      Width:   ${WIDTH} MHz"

# Bring down monitor adapter if up
echo "[2/5] Bringing down $MONITOR_PHY..."
ip link set $MONITOR_PHY down 2>/dev/null || true

# Delete any existing monitor interface
echo "[3/5] Cleaning up old monitor interfaces..."
iw dev $MONITOR_IF del 2>/dev/null || true

# Create monitor interface
echo "[4/5] Creating monitor interface $MONITOR_IF from $MONITOR_PHY..."
iw dev $MONITOR_PHY interface add $MONITOR_IF type monitor
ip link set $MONITOR_IF up

# Set channel and bandwidth to match managed interface
echo "[5/5] Setting $MONITOR_IF to channel $CHANNEL, width ${WIDTH} MHz..."
if [ "$WIDTH" == "20" ]; then
    iw dev $MONITOR_IF set channel $CHANNEL HT20
elif [ "$WIDTH" == "40" ]; then
    iw dev $MONITOR_IF set channel $CHANNEL HT40+
elif [ "$WIDTH" == "80" ]; then
    iw dev $MONITOR_IF set channel $CHANNEL 80MHz
elif [ "$WIDTH" == "160" ]; then
    iw dev $MONITOR_IF set channel $CHANNEL 160MHz
else
    # Fallback to basic channel setting
    iw dev $MONITOR_IF set channel $CHANNEL
fi

echo ""
echo "✓ Setup complete!"
echo ""
echo "Interface configuration:"
iw dev $MANAGED_IF info | grep -E "Interface|channel|ssid"
echo "---"
iw dev $MONITOR_IF info | grep -E "Interface|channel|type"
echo ""
echo "Ready to capture!"
echo "Run: sudo ./ping_ack_latency -i $MANAGED_IF -m $MONITOR_IF -g <gateway_ip>"
echo ""
