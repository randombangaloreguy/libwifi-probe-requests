#include <libwifi.h>

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


static int has_radiotap = 0;
static unsigned int pkt_num;

int print_tag_info(unsigned char *tag_data, size_t tag_data_len) {
    // Initialise a libwifi_tag_iterator
    struct libwifi_tag_iterator it = {0};
    if (libwifi_tag_iterator_init(&it, tag_data, tag_data_len) != 0) {
        return -1; 
    }   

    do {
        printf("%d:%s:%d, ", it.tag_header->tag_num,
                                              libwifi_get_tag_name(it.tag_header->tag_num),
                                              it.tag_header->tag_len);

        int max_size = 16; 
        if (it.tag_header->tag_len < 16) {
            max_size = it.tag_header->tag_len;
        }   
        //printf("\t\t%d bytes of Tag Data: ", max_size);
        for (size_t i = 0; i < max_size; i++) {
            printf("%02x ", it.tag_data[i]);
        }   
        printf(", ");
    } while (libwifi_tag_iterator_next(&it) != -1);

    return 0;
}

void print_sta_info(struct libwifi_sta *sta) {
    if (sta == NULL) {
        return;
    }   

    printf("%d, ", pkt_num);
    printf("%d, ", sta->channel);
    if (sta->broadcast_ssid) {
        printf("<broadcast>, ");
    } else {
        printf("%s, ", sta->ssid);
    }   
    //printf(MACSTR ", ", MAC2STR(sta->bssid));
    printf(MACSTR ", ", MAC2STR(sta->transmitter));
    printf(MACSTR ", ", MAC2STR(sta->receiver));
    printf("%d, ", sta->randomized);
}   

void handle_pkt(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    pkt_num++;
    unsigned long data_len = header->caplen;
    unsigned char *data = (unsigned char *) packet;
    
    // Initialise a libwifi_frame struct and populate it
    struct libwifi_frame frame = {0};
    int ret = libwifi_get_wifi_frame(&frame, data, data_len, has_radiotap);
    if (ret != 0) {
        return;
    }   
    
    // Ensure the frame is a Probe Request frame
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_PROBE_REQ) {
        // Initalise a libwifi_bss struct and populate it with the data from the sniffed frame
        struct libwifi_sta sta = {0};
        ret = libwifi_parse_probe_req(&sta, &frame);
        if (ret != 0) {
            return;
        }   
        
        print_sta_info(&sta);
        
        // If any tagged parameters are available for this frame, we can iterate through them
        // since libwifi will automatically find them.
        if (sta.tags.length) {
            //printf("Tagged Parameters:\n");
            print_tag_info(sta.tags.parameters, sta.tags.length);
        } else {
            printf("Tagged Parameters: None,");
        }   
        
        // Cleanup the libwifi bss
        libwifi_free_sta(&sta);
        printf("\n");
    }
    // Clean up the libwifi frame
    libwifi_free_wifi_frame(&frame);
}

void helpexit(char *name) {
    fprintf(stderr, "[!] Usage: %s [-l] [-u] [-i <file.pcap>] [-d <directory>] [-w <output-filename.pcap>]\n", name);
    //fprintf(stderr, "Usage: %s [-l] [-u] [-i filename] [-w outputFilename]\n", argv[0]);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    int opt;
    char *inputFilename = NULL;
    char *outputFilename = NULL;
    char *inputDirname = NULL;

    int listFlag = 0;
    int uniqueFlag = 0;

    while ((opt = getopt(argc, argv, "lui:d:w:")) != -1) {
        switch (opt) {
            case 'l':
                listFlag = 1;
                break;
            case 'u':
                uniqueFlag = 1;
                break;
            case 'i':
                inputFilename = optarg;
                break;
            case 'd':
                inputDirname = optarg;
                break;
            case 'w':
                outputFilename = optarg;
                break;
            default:
                helpexit(argv[0]);
        }
    }

    fprintf(stdout, "Input file  - %s\n", inputFilename);
    fprintf(stdout, "Input Dir   - %s\n", inputDirname);
    fprintf(stdout, "Output file - %s\n", outputFilename);
    
    fprintf(stdout, "List Flag   - %d\n", listFlag);
    fprintf(stdout, "Unique Flag - %d\n", uniqueFlag);
    
    /*
    *
    * Do following tasks - 
    * 1. Given a pcap file provide option to dump probe requests coming from all unique sources
    * 2. Given a directory, read all the pcap files within and dump probe requests coming from all unique sources
    * 3. Given a pcap file, dump all unique probes (1 from each mac) into another pcap file
    * 4. Given a pcap containing unique probe requests, convert it into dataset in csv format
    */
    pcap_t *handle = NULL;
    pcap_dumper_t *dumper = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (argc < 2) {
        helpexit(argv[0]);
    }
    if (strcmp(argv[1], "--file") == 0) {
        if ((handle = pcap_open_offline(argv[2], errbuf)) == NULL) {
            fprintf(stderr, "[!] Error opening file %s (%s)\n", argv[2], errbuf);
            exit(EXIT_FAILURE);
        }
    } else {
        helpexit(argv[0]);
    }

    int linktype = pcap_datalink(handle);
    if (linktype == DLT_IEEE802_11_RADIO) {
        has_radiotap = 1;
    }
    if (linktype != DLT_IEEE802_11 && linktype != DLT_IEEE802_11_RADIO) {
        fprintf(stderr, "[!] 802.11 and radiotap headers not provided (%d)\n", pcap_datalink(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    //printf("[+] Setup Complete\n");

    dumper = pcap_dump_open(handle, "/tmp/parse_probe.pcap");
    pcap_loop(handle, -1 /*INFINITY*/, &handle_pkt, (unsigned char *) dumper);

    pcap_dump_close(dumper);
    pcap_close(handle);
    return 0;
}
