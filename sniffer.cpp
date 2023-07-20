#include <pcap.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header;
        ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
        

        if(ip_header->ip_p == 1 ){
            printf("icmp packet captured \n");
            printf("IP Src: %s\n", inet_ntoa(ip_header->ip_src));
            printf("IP Dst: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("------------------------------------------------\n");
            
        }
    }
}

int main() {
    char *dev;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    dev = "ens33";
    if (dev == NULL) {
        printf("Device not found: %s\n", error_buffer);
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 100, error_buffer);
    if (handle == NULL) {
        printf("Error opening device: %s\n", error_buffer);
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    return 0;
}