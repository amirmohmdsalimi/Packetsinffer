#include <pcap.h>
#include <vector>
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


    pcap_if_t *alldevs;
    pcap_if_t *d;
    char *dev;
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int i = 1;int inum;
    std::vector<pcap_if_t*> devs;



    if (pcap_findalldevs(&alldevs, error_buffer) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", error_buffer);
        return 1;
    }

    for (d = alldevs; d; d = d->next) {
        printf("%d-%s\n",i, d->name);
        devs.push_back(d);
        i = i+1;
    }
    printf("enter the network card number:");
    scanf("%d", &inum);
    if(inum < 1 || inum > i-1){
        printf("wrong number.");
        pcap_freealldevs(alldevs);
        return 0;

    }


    // dev = "ens33";
    // if (dev == NULL) {
    //     printf("Device not found: %s\n", error_buffer);
    //     return 1;
    // }

    handle = pcap_open_live(devs[inum-1]->name, BUFSIZ, 1, 100, error_buffer);
    if (handle == NULL) {
        printf("Error opening device: %s\n", error_buffer);
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_freealldevs(alldevs);


    return 0;
}