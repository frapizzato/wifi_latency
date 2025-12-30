#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>

// Radiotap header structures
#define IEEE80211_RADIOTAP_TSFT 0
#define IEEE80211_RADIOTAP_FLAGS 1
#define IEEE80211_RADIOTAP_RATE 2
#define IEEE80211_RADIOTAP_CHANNEL 3
#define IEEE80211_RADIOTAP_DBM_ANTSIGNAL 5
#define IEEE80211_RADIOTAP_DBM_ANTNOISE 6

// 802.11 frame types
#define IEEE80211_FTYPE_DATA 0x08
#define IEEE80211_FTYPE_CTL 0x04
#define IEEE80211_STYPE_ACK 0xd0
#define IEEE80211_STYPE_QOS_DATA 0x88

// Maximum number of unmatched DATA frames to track
#define MAX_PENDING_FRAMES 1000

struct radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((__packed__));

struct ieee80211_hdr {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} __attribute__((__packed__));

struct pending_frame {
    uint64_t timestamp;
    uint16_t seq_num;
    int valid;
};

// Global variables
static pcap_t *handle = NULL;
static int keep_running = 1;
static uint8_t local_mac[6];
static char *gateway_ip = NULL;
static struct pending_frame pending_frames[MAX_PENDING_FRAMES];
static int num_pending = 0;

// Statistics
static struct {
    uint64_t data_frames_sent;
    uint64_t ack_frames_recv;
    uint64_t matched_pairs;
    uint64_t unmatched_data;
    uint64_t unmatched_ack;
    double total_latency_us;
    double min_latency_us;
    double max_latency_us;
} stats = {0, 0, 0, 0, 0, 0.0, 1e9, 0.0};

void signal_handler(int signum) {
    printf("\nReceived signal %d, stopping capture...\n", signum);
    keep_running = 0;
    if (handle) {
        pcap_breakloop(handle);
    }
}

void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int get_interface_mac(const char *ifname, uint8_t *mac) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

uint64_t parse_radiotap_timestamp(const uint8_t *packet, int *has_tsft) {
    struct radiotap_header *rt_hdr = (struct radiotap_header *)packet;
    uint32_t present = rt_hdr->it_present;
    const uint8_t *pos = packet + sizeof(struct radiotap_header);
    uint64_t timestamp = 0;
    
    *has_tsft = 0;
    
    // Check if TSFT is present
    if (present & (1 << IEEE80211_RADIOTAP_TSFT)) {
        *has_tsft = 1;
        // TSFT must be aligned to 8 bytes
        int offset = (pos - packet) % 8;
        if (offset != 0) {
            pos += (8 - offset);
        }
        memcpy(&timestamp, pos, 8);
    }
    
    return timestamp;
}

void process_data_frame(const uint8_t *packet, int packet_len, uint64_t timestamp) {
    struct radiotap_header *rt_hdr = (struct radiotap_header *)packet;
    
    if (packet_len < rt_hdr->it_len + sizeof(struct ieee80211_hdr)) {
        return;
    }
    
    struct ieee80211_hdr *wlan_hdr = (struct ieee80211_hdr *)(packet + rt_hdr->it_len);
    
    // Check if source MAC matches our interface
    if (memcmp(wlan_hdr->addr2, local_mac, 6) == 0) {
        uint16_t seq_num = (wlan_hdr->seq_ctrl >> 4) & 0x0fff;
        
        // Store this DATA frame as pending
        if (num_pending < MAX_PENDING_FRAMES) {
            pending_frames[num_pending].timestamp = timestamp;
            pending_frames[num_pending].seq_num = seq_num;
            pending_frames[num_pending].valid = 1;
            num_pending++;
            stats.data_frames_sent++;
        }
    }
}

void process_ack_frame(const uint8_t *packet, int packet_len, uint64_t timestamp) {
    struct radiotap_header *rt_hdr = (struct radiotap_header *)packet;
    
    if (packet_len < rt_hdr->it_len + 10) { // ACK frame is smaller
        return;
    }
    
    // ACK frame format: frame_control (2) + duration (2) + addr1 (6)
    const uint8_t *ack_frame = packet + rt_hdr->it_len;
    const uint8_t *dest_mac = ack_frame + 4;
    
    // Check if destination MAC matches our interface
    if (memcmp(dest_mac, local_mac, 6) == 0) {
        stats.ack_frames_recv++;
        
        // Find the closest preceding DATA frame
        int best_match = -1;
        uint64_t min_time_diff = UINT64_MAX;
        
        for (int i = 0; i < num_pending; i++) {
            if (pending_frames[i].valid && timestamp > pending_frames[i].timestamp) {
                uint64_t time_diff = timestamp - pending_frames[i].timestamp;
                if (time_diff < min_time_diff) {
                    min_time_diff = time_diff;
                    best_match = i;
                }
            }
        }
        
        if (best_match >= 0) {
            // Calculate latency in microseconds
            double latency_us = min_time_diff / 1.0;
            
            stats.matched_pairs++;
            stats.total_latency_us += latency_us;
            
            if (latency_us < stats.min_latency_us) {
                stats.min_latency_us = latency_us;
            }
            if (latency_us > stats.max_latency_us) {
                stats.max_latency_us = latency_us;
            }
            
            // Mark this frame as matched
            pending_frames[best_match].valid = 0;
            
            // Print real-time update
            printf("ACK matched! Latency: %.2f µs (avg: %.2f µs, min: %.2f µs, max: %.2f µs)\n",
                   latency_us,
                   stats.total_latency_us / stats.matched_pairs,
                   stats.min_latency_us,
                   stats.max_latency_us);
        } else {
            stats.unmatched_ack++;
        }
        
        // Cleanup old pending frames
        if (num_pending > MAX_PENDING_FRAMES * 0.8) {
            int write_idx = 0;
            for (int i = 0; i < num_pending; i++) {
                if (pending_frames[i].valid) {
                    if (write_idx != i) {
                        pending_frames[write_idx] = pending_frames[i];
                    }
                    write_idx++;
                }
            }
            num_pending = write_idx;
        }
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int has_tsft = 0;
    uint64_t timestamp = parse_radiotap_timestamp(packet, &has_tsft);
    
    if (!has_tsft) {
        // If no MAC timestamp, use capture time (less precise)
        timestamp = (uint64_t)header->ts.tv_sec * 1000000ULL + (uint64_t)header->ts.tv_usec;
    }
    
    struct radiotap_header *rt_hdr = (struct radiotap_header *)packet;
    
    if (header->caplen < rt_hdr->it_len + 2) {
        return;
    }
    
    const uint8_t *wlan_frame = packet + rt_hdr->it_len;
    uint16_t frame_control = wlan_frame[0] | (wlan_frame[1] << 8);
    uint8_t frame_type = frame_control & 0x0c;
    uint8_t frame_subtype = frame_control & 0xf0;
    
    // Debug: print frame types (comment out after testing)
    static int debug_counter = 0;
    if (debug_counter++ < 20) {
        printf("Frame: type=0x%02x subtype=0x%02x fc=0x%04x\n", 
               frame_type, frame_subtype, frame_control);
    }
    
    if (frame_type == IEEE80211_FTYPE_DATA) {
        // Accept any DATA frame variant
        process_data_frame(packet, header->caplen, timestamp);
    } else if (frame_type == IEEE80211_FTYPE_CTL && frame_subtype == IEEE80211_STYPE_ACK) {
        process_ack_frame(packet, header->caplen, timestamp);
    }
}

void print_statistics() {
    printf("\n");
    printf("=================================\n");
    printf("     LATENCY STATISTICS\n");
    printf("=================================\n");
    printf("DATA frames sent:      %lu\n", stats.data_frames_sent);
    printf("ACK frames received:   %lu\n", stats.ack_frames_recv);
    printf("Matched pairs:         %lu\n", stats.matched_pairs);
    printf("Unmatched DATA frames: %lu\n", stats.unmatched_data);
    printf("Unmatched ACKs:        %lu\n", stats.unmatched_ack);
    
    if (stats.matched_pairs > 0) {
        printf("\n--- Latency Measurements ---\n");
        printf("Average latency:       %.2f µs\n", stats.total_latency_us / stats.matched_pairs);
        printf("Minimum latency:       %.2f µs\n", stats.min_latency_us);
        printf("Maximum latency:       %.2f µs\n", stats.max_latency_us);
    }
    printf("=================================\n");
}

void usage(const char *progname) {
    fprintf(stderr, "Usage: %s -i <monitor_interface> -m <managed_interface> [-g <gateway_ip>]\n", progname);
    fprintf(stderr, "  -i <monitor_interface>  : Monitor interface to capture on (e.g., mon0)\n");
    fprintf(stderr, "  -m <managed_interface>  : Managed interface MAC to track (e.g., wlan0)\n");
    fprintf(stderr, "  -g <gateway_ip>         : Gateway IP (optional, for future filtering)\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  sudo %s -i mon0 -m wlan0 -g 192.168.0.1\n", progname);
    exit(1);
}

int main(int argc, char *argv[]) {
    char *mon_interface = NULL;
    char *managed_interface = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    int opt;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:m:g:h")) != -1) {
        switch (opt) {
            case 'i':
                mon_interface = optarg;
                break;
            case 'm':
                managed_interface = optarg;
                break;
            case 'g':
                gateway_ip = optarg;
                break;
            case 'h':
            default:
                usage(argv[0]);
        }
    }
    
    if (!mon_interface || !managed_interface) {
        usage(argv[0]);
    }
    
    // Get MAC address of managed interface
    if (get_interface_mac(managed_interface, local_mac) < 0) {
        fprintf(stderr, "Failed to get MAC address of %s\n", managed_interface);
        return 1;
    }
    
    printf("Monitor interface: %s\n", mon_interface);
    printf("Managed interface: %s (MAC: ", managed_interface);
    print_mac(local_mac);
    printf(")\n");
    if (gateway_ip) {
        printf("Gateway IP: %s\n", gateway_ip);
    }
    printf("\nStarting packet capture...\n");
    printf("Send ICMP pings from another terminal using:\n");
    printf("  ping -I %s <gateway_ip>\n\n", managed_interface);
    
    // Open capture device
    handle = pcap_open_live(mon_interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", mon_interface, errbuf);
        return 1;
    }
    
    // Check if we're capturing on a monitor mode interface
    int linktype = pcap_datalink(handle);
    if (linktype != DLT_IEEE802_11_RADIO) {
        fprintf(stderr, "Error: Interface is not in monitor mode (linktype: %d)\n", linktype);
        fprintf(stderr, "Expected DLT_IEEE802_11_RADIO (%d)\n", DLT_IEEE802_11_RADIO);
        pcap_close(handle);
        return 1;
    }
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("Starting packet capture loop... Press Ctrl+C to stop.\n\n");
    
    // Start packet capture with callback checking
    int ret;
    while (keep_running) {
        ret = pcap_dispatch(handle, 10, packet_handler, NULL);
        if (ret < 0) {
            fprintf(stderr, "Error in pcap_dispatch: %s\n", pcap_geterr(handle));
            break;
        }
        if (ret == 0) {
            usleep(1000); // Sleep 1ms if no packets
        }
    }
    
    // Cleanup
    printf("\n\nCapture stopped. Calculating statistics...\n");
    
    // Count unmatched DATA frames
    for (int i = 0; i < num_pending; i++) {
        if (pending_frames[i].valid) {
            stats.unmatched_data++;
        }
    }
    
    print_statistics();
    
    pcap_close(handle);
    return 0;
}
