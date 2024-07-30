#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define ETHERNET_HEADER_SIZE 14
#define IP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 20

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];
    u_int8_t  ether_shost[ETHER_ADDR_LEN];
    u_int16_t ether_type;
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4,
             ip_v:4;
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
    u_int8_t th_x2:4,
             th_off:4;
    u_int8_t  th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
};

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac(u_int8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(const u_char* payload, int len) {
    int print_len = len < 20 ? len : 20;
    for (int i = 0; i < print_len; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        if (ntohs(eth_hdr->ether_type) != 0x0800) continue; // Not IP

        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + ETHERNET_HEADER_SIZE);
        if (ip_hdr->ip_p != 6) continue; // Not TCP

        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE);

        printf("Ethernet Header\n");
        printf("   Src MAC: ");
        print_mac(eth_hdr->ether_shost);
        printf("\n   Dst MAC: ");
        print_mac(eth_hdr->ether_dhost);
        printf("\n");

        printf("IP Header\n");
        printf("   Src IP: %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("   Dst IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

        printf("TCP Header\n");
        printf("   Src Port: %d\n", ntohs(tcp_hdr->th_sport));
        printf("   Dst Port: %d\n", ntohs(tcp_hdr->th_dport));

        int ip_header_len = (ip_hdr->ip_hl & 0x0f) * 4;
        int tcp_header_len = ((tcp_hdr->th_off & 0xf0) >> 4) * 4;
        int total_headers_size = ETHERNET_HEADER_SIZE + ip_header_len + tcp_header_len;
        int payload_len = header->caplen - total_headers_size;

        printf("Payload (first 20 bytes)\n");
        if (payload_len > 0) {
            const u_char* payload = packet + total_headers_size;
            print_payload(payload, payload_len);
        } else {
            printf("No payload\n");
        }
        printf("\n");
    }

    pcap_close(pcap);
}