#include <pcap.h>
#include <stdio.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
}

int main() {
    char *dev;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    dev = pcap_lookupdev(error_buffer);
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