# WiFi DATA-ACK Latency Monitor

Experimental tool to measure WiFi MAC-layer acknowledgment latencies using dual-interface monitoring. Tracks DATA frames from a managed interface and matches them with corresponding ACK frames captured on a monitor interface.

## Repository content


### ping_ack_latency
Main monitoring program that captures 802.11 frames and measures DATA-ACK latencies.

Notice that program could be compiled with the given makefile using ``make``.

**Usage:**
```bash
sudo ./ping_ack_latency -i <managed_interface> -m <monitor_interface> [-v]
```

Options:
- `-i`: Managed interface (e.g., wlp0s20f3) - for MAC filtering
- `-m`: Monitor interface (e.g., mon0) - for packet capture  
- `-v`: Verbose debug output (optional)

**Example:**
```bash
# Terminal 1: Start monitor
sudo ./ping_ack_latency -i wlp0s20f3 -m mon0

# Terminal 2: Generate traffic
ping -I wlp0s20f3 192.168.0.1
```

The tool monitors all DATA frames (not just pings) since traffic is encrypted. Press Ctrl+C to stop and view statistics.

The tool uses two interfaces: one maintains your WiFi connection while the other passively captures all 802.11 frames. It filters DATA frames by source MAC and ACK frames by destination MAC, then matches them based on capture timestamps. A sliding window tracks up to 1000 pending DATA frames, matching each ACK to the most recent DATA within a 10ms window. 

### setup_dual_interface.sh
Automated setup script that creates a monitor interface from your USB adapter and matches channel settings with the managed interface.

**Usage:**
```bash
sudo ./setup_dual_interface.sh
```

Edit these variables in the script for your hardware:
```bash
MANAGED_IF="wlp0s20f3"         # Your primary WiFi interface
MONITOR_PHY="wlxe84e06b0d13b"  # Your USB WiFi adapter name
MONITOR_IF="mon0"              # Desired monitor interface name
```

### cleanup_dual_interface.sh
Removes the monitor interface setup while preserving your managed interface connection.

**Usage:**
```bash
sudo ./cleanup_dual_interface.sh
```

### setup_monitor.sh / cleanup_monitor.sh
Alternative single-interface setup (using a single physical interface and two virtual ones):

```bash
sudo ./setup_monitor.sh <interface> <monitor_name>
sudo ./cleanup_monitor.sh <monitor_interface>
```
