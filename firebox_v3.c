#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h> // Required for ETH_P_ALL

#define BLOCKED_IP "8.8.8.8"
#define LOG_FILE "firewall_alerts.log"

/* Custom IP Header Struct (Matching Erickson's Book) */
struct ip_hdr {
    unsigned char  ip_hl:4, ip_v:4;
    unsigned char  ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    unsigned char  ip_ttl;
    unsigned char  ip_p;
    unsigned short ip_sum;
    struct in_addr ip_src, ip_dst;
};

/* Professional Logging Function */
void log_event(char *ip, char *status) {
    FILE *f = fopen(LOG_FILE, "a");
    if (f == NULL) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    fprintf(f, "[%s] ACTION: %s | SOURCE: %s\n", timestamp, status, ip);
    fclose(f);
}

int main() {
    int sockfd;
    unsigned char buffer[65536]; // Max packet size
    struct ip_hdr *ip;

    // Create a Packet Socket to catch EVERY protocol (ICMP, TCP, UDP)
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd < 0) {
        perror("Error: Run as sudo");
        exit(1);
    }

    // Ensure log file exists immediately
    fclose(fopen(LOG_FILE, "a"));

    printf("\n🛡️  FIREBOX V3 ACTIVE\n");
    printf("📡 Monitoring all interfaces...\n");
    printf("🚫 Blacklist Target: %s\n", BLOCKED_IP);
    printf("📝 Logging to: %s\n\n", LOG_FILE);

    while(1) {
        int length = recv(sockfd, buffer, 65536, 0);
        if (length < 0) continue;

        /* OFFSET: We are using PF_PACKET, so the buffer starts with:
           [Ethernet Header (14 bytes)][IP Header (20 bytes)][Data]
        */
        ip = (struct ip_hdr *)(buffer + 14);

        // Convert the binary IP to a string for comparison
        char *src_ip = inet_ntoa(ip->ip_src);

        if (strcmp(src_ip, BLOCKED_IP) == 0) {
            printf("\033[1;31m[BLOCK]\033[0m Packet from %s dropped.\n", src_ip);
            log_event(src_ip, "BLOCKED");
        } 
        // Optional: uncomment to see all traffic
        // else { printf("[PASS] From %s\n", src_ip); }
    }
    return 0;
}
