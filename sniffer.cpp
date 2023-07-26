#include <pcap.h>
#include <vector>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

pcap_t *handle;


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


void *key_monitor(void *arg) {

    struct termios old_termios, new_termios;

    tcgetattr(STDIN_FILENO, &old_termios);

    new_termios = old_termios;

    new_termios.c_lflag &= ~(ICANON | ECHO);

    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

    while (1) {
        int ch = getchar();

        if (ch == 1) {
            pcap_breakloop(handle);
            break;
        }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);


    return NULL;
}


int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char *dev;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pthread_t thread;
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
    handle = pcap_open_live(devs[inum-1]->name, BUFSIZ, 1, 100, error_buffer);
    if (handle == NULL) {
        printf("Error opening device: %s\n", error_buffer);
        return 2;
    }
    
    pthread_create(&thread, NULL, key_monitor, NULL);
    pcap_loop(handle, 0, packet_handler, NULL);
    pthread_join(thread, NULL);

    

    pcap_freealldevs(alldevs);

    return 0;


}