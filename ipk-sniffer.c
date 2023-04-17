#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include<pcap/pcap.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<netinet/ether.h>
#include<netinet/ip6.h>
#include<netinet/tcp.h>
#include <netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>

pcap_t* devopen;

struct ProgramArgs
{
    char* interface;
    int port;
    int number;
    bool tcp;
    bool udp;
    bool arp;
    bool icmp4;
    bool icmp6;
    bool igmp;
    bool mld;
    bool ndp;
};

int Error()
{
    printf("Error in arguments, use -h or --help.\n");
    return 1;
}

int print_interfaces()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_if_t *interfaces, *device;

        if (pcap_findalldevs(&interfaces, error_buffer) == -1) 
        {
            printf("Error in pcap_findalldevs(): %s", error_buffer);
            return 1;
        }
        
        for (device = interfaces; device != NULL; device = device->next) {
            printf("%s\n", device->name);
        }

        pcap_freealldevs(interfaces);
        return 0;
}

int parsing_args(int argc, char *argv[], struct ProgramArgs *args)
{
    if (argc < 3 && strcmp(argv[1], "-h") != 0 && strcmp(argv[1], "--help") != 0)
    {
        if (strcmp(argv[1], "-i") != 0 && strcmp(argv[1], "--interface") != 0)
        {
            printf("Network interfaces not found.\n");
            printf("Usage:\n");
            printf("./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
            return 1;
        }
        else{print_interfaces(); exit(0);}
    }
    else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
    {
        printf("Usage:\n");
        printf("./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
        printf("-i [string]   specify an interface\n");
        printf("-n [integer]  set packet limit (unlimited if not set)\n");
        printf("-p [integer]  set packet port to filter\n");
        printf("-u            filter only UDP packets\n");
        printf("-t            filter only TCP packets\n");
        exit(0);
    }
    int i = 1;
    while (i < argc)
    {
        if (strcmp(argv[i], "--tcp") == 0 || strcmp(argv[i], "-t") == 0) 
        {
            if (args->tcp){Error();}
            args->tcp = true;
        }
        else if (strcmp(argv[i], "--udp") == 0 || strcmp(argv[i], "-u") == 0) 
        {
            if (args->udp){Error();}
            args->udp = true;
        }
        else if (strcmp(argv[i], "--arp") == 0) 
        {
            if (args->arp){Error();}
            args->arp = true;
        }
        else if (strcmp(argv[i], "--icmp4") == 0) 
        {
            if (args->icmp4){Error();}
            args->icmp4 = true;
        }
        else if (strcmp(argv[i], "--icmp6") == 0) 
        {
            if (args->icmp6){Error();}
            args->icmp6 = true;
        }
        else if (strcmp(argv[i], "--igmp") == 0) 
        {
            if (args->igmp){Error();}
            args->igmp = true;
        }
        else if (strcmp(argv[i], "--mld") == 0) 
        {
            if (args->mld){Error();}
            args->mld = true;
        }
        else if (strcmp(argv[i], "--ndp") == 0) 
        {
            if (args->ndp){Error();}
            args->ndp = true;
        }
        else if (strcmp(argv[i], "-i") == 0) 
        {
            if ((i+1) < argc)
            {
                if (argv[i+1][0] != '-')
                {
                    strcpy(args->interface, argv[i+1]);
                    i++;
                }
                else{args->interface = "";}
            }
        }
        else if (strcmp(argv[i], "-n") == 0) 
        {
            if (args->number != 1){Error();}
            if ((i+1) < argc)
            {
                if (atoi(argv[i+1]) < 1)
                {
                    printf("Invalid n number, number has to be > than 0\n");
                    exit(1);
                }
                if (argv[i+1][0] != '-')
                {
                    args->number = atoi(argv[i+1]);
                    i++;
                }
            }
        }
        else if (strcmp(argv[i], "-p") == 0) 
        {
            if (args->port != -1){Error();}
            if ((i+1) < argc)
            {
                if (atoi(argv[i+1]) < 0)
                {
                    printf("Invalid port number, number has to be >= than 0\n");
                    exit(1);
                }
                if (argv[i+1][0] != '-')
                {
                    args->port = atoi(argv[i+1]);
                    i++;
                }
            }
        }
        else
        {
            printf("Unknown program argument\n");
            return 1;
        }
        i++;
    }

    if (strlen(args->interface) == 0){print_interfaces();exit(0);}
    return 0;
}

pcap_t* work_with_device(struct ProgramArgs *args)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32  device_ip, netmask;
    struct bpf_program fp;
    char filter_exp[100];

    if (pcap_lookupnet(args->interface, &device_ip, &netmask, errbuf) == -1)
    {
        printf("Error with  ip and netmask of device: %s\n", errbuf);
        return NULL;
    }

    devopen = pcap_open_live(args->interface, BUFSIZ, 1, 1000, errbuf);
    if (devopen == NULL)
    {
        printf("Error with  openning device: %s\n", errbuf);
        return NULL;
    }

    if(pcap_datalink(devopen) != DLT_EN10MB)
    {
        printf("Interface does not provide Ethernet headers");
        return NULL;
    }
    
    if (!(args->arp || args->icmp4 || args->icmp6 || args->igmp || args->mld || args->ndp || args->tcp || args->udp))
    {
        args->arp = true;
        args->icmp4 = true;
        args->icmp6 = true;
        args->igmp = true;
        args->mld = true;
        args->ndp = true;
        args->tcp = true;
        args->udp = true;
    }

    if (args->tcp && args->udp) 
    {
        if (args->port == -1) {sprintf(filter_exp, "(tcp and portrange 0-65535) or (udp and portrange 0-65535)");} 
        else {sprintf(filter_exp, "(tcp and port %d) or (udp and port %d)", args->port, args->port); }
    } 
    else if (args->tcp) 
    {
        if (args->port == -1) {sprintf(filter_exp, "(tcp and portrange 0-65535)");} 
        else {sprintf(filter_exp, "(tcp and port %d)", args->port);}
    } 
    else if (args->udp) 
    {
        if (args->port == -1) {sprintf(filter_exp, "(udp and portrange 0-65535)");}
        else {sprintf(filter_exp, "(udp and port %d)", args->port);}
    }
    if (args->arp) 
    {
        if (filter_exp[0] == '\0') {sprintf(filter_exp, "arp");}
        else {strcat(filter_exp, " or arp");}
    }
    if (args->igmp) 
    {
        if (filter_exp[0] == '\0') {sprintf(filter_exp, "igmp");}
        else {strcat(filter_exp, " or igmp");}
    }
    if (args->mld) {
        if (filter_exp[0] == '\0') { sprintf(filter_exp, "(icmp6 and (icmp6[0] >= 130 and icmp6[0] <= 132))"); }
        else { strcat(filter_exp, " or (icmp6 and (icmp6[0] >= 130 and icmp6[0] <= 132))"); }
    }
    if (args->ndp) {
        if (filter_exp[0] == '\0') { sprintf(filter_exp, "(icmp6 and (icmp6[0] >= 133 and icmp6[0] <= 137))"); }
        else { strcat(filter_exp, " or (icmp6 and (icmp6[0] >= 133 and icmp6[0] <= 137))"); }
    }
    if (args->icmp4) 
    {
        if (filter_exp[0] == '\0') {sprintf(filter_exp, "icmp");} 
        else {strcat(filter_exp, " or icmp");}
    }
    if (args->icmp6) 
    {
        if (filter_exp[0] == '\0') {sprintf(filter_exp, "icmp6");} 
        else {strcat(filter_exp, " or icmp6");}
    }
    if(pcap_compile(devopen, &fp, filter_exp, 0, device_ip) == -1) 
    {
        printf("Error: compile failed (%s)\n", pcap_geterr(devopen));
        return NULL;
    }
    if(pcap_setfilter(devopen, &fp) == -1)
	{
		printf("Error: setting filter failed (%s)\n", pcap_geterr(devopen));
		return NULL;
	}
    return devopen;
}

int main(int argc, char* argv[])
{
    if (argc == 1){Error();}
    struct ProgramArgs args = {
        .interface = NULL,
        .port = -1,
        .number = 1,
        .tcp = false,
        .udp = false,
        .arp = false,
        .icmp4 = false,
        .icmp6 = false,
        .igmp = false,
        .mld = false,
        .ndp = false
    };
    args.interface = malloc(20 * sizeof(char));
    int parse_result = parsing_args(argc, argv, &args);
    if (parse_result != 0)
    {
        free(args.interface);
        return 1;
    }
    devopen = work_with_device(&args);
    if (devopen != NULL) {
        struct pcap_pkthdr header;
        const u_char* packet;

        int k = 0;
        while (k < args.number) {
            packet = pcap_next(devopen, &header);
            struct ether_header* ethernet;
            ethernet = (struct ether_header*)(packet);
            char src_ip[100] = {'\0'};
            char dst_ip[100] = {'\0'};
            char src_ip6[100] = {'\0'};
            char dst_ip6[100] = {'\0'};
            char time[100] = {'\0'};
	        strftime(time,sizeof(time),"%H:%M:%S", localtime(&header.ts.tv_sec));
            printf("%s.%ld\n",time, (long)header.ts.tv_usec );
            uint8_t* ptr;

            // Print source MAC address
            ptr = ethernet->ether_shost;
            printf("src MAC:");
            for (int i = ETHER_ADDR_LEN; i > 0; i--) {
                if (i == ETHER_ADDR_LEN) {
                    printf(" ");
                }
                else {
                    printf(":");
                }
                printf("%02X", *ptr++);
            }
            printf("\n");


            // Print destination MAC address
            ptr = ethernet->ether_dhost;
            printf("dst MAC:");
            for (int i = ETHER_ADDR_LEN; i > 0; i--) {
                if (i == ETHER_ADDR_LEN) {
                    printf(" ");
                }
                else {
                    printf(":");
                }
                printf("%02X", *ptr++);
            }
            printf("\n");

            // Print frame length
            printf("frame length: %d bytes\n", header.len);

            if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
                struct ip* ipHeader;
                ipHeader = (struct ip*)(packet + 14);
                // Print source and destination IP addresses
                inet_ntop(AF_INET, &ipHeader->ip_src, src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &ipHeader->ip_dst, dst_ip, INET_ADDRSTRLEN);
                printf("src IP: %s\n", src_ip);
                printf("dst IP: %s\n", dst_ip);
                if (ipHeader->ip_p == IPPROTO_TCP) {
                    struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14);
                    printf("src port: %d\n", ntohs(tcp_header->th_sport));
                    printf("dst port: %d\n", ntohs(tcp_header->th_dport));
                }
                else if (ipHeader->ip_p == IPPROTO_UDP) {
                    struct udphdr* udp_header = (struct udphdr*)(packet + 14);
                    printf("src port: %d\n", ntohs(udp_header->uh_sport));
                    printf("dst port: %d\n", ntohs(udp_header->uh_dport));
                }
                // else if (ipHeader->ip_p == 1) {
                //     struct icmphdr* icmp_header = (struct icmphdr*)(packet + 14);
                // }
            }
            else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
                struct ether_arp* arp_header = (struct ether_arp*)(packet + 14);
                char arpbuf1[100] = { '\0' };
                char arpbuf2[100] = { '\0' };
                printf("src IP: %s\n", inet_ntop(AF_INET, arp_header->arp_spa, arpbuf1, 100));
                printf("dst IP: %s\n", inet_ntop(AF_INET, arp_header->arp_tpa, arpbuf2, 100));
            }
            else if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV6) {
                struct ip6_hdr* ip6_header = (struct ip6_hdr*)(packet + 14);
                inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip6, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip6, INET6_ADDRSTRLEN);
                printf("src IP: %s\n", src_ip6);
                printf("dst IP: %s\n", dst_ip6);

                if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP) {
                    struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + 40);
                    printf("src port: %d\n", ntohs(tcp_header->th_sport));
                    printf("dst port: %d\n", ntohs(tcp_header->th_dport));
                }
                else if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP) {
                    struct udphdr* udp_header = (struct udphdr*)(packet + 14 + 40);
                    printf("src port: %d\n", ntohs(udp_header->uh_sport));
                    printf("dst port: %d\n", ntohs(udp_header->uh_dport));
                }
                // else if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58) {
                //     struct icmphdr* icmp_header = (struct icmphdr*)(packet + 14);
                // }
            }

            char asciiprint[17] = { '\0' };
            int j = 0;
            while (j < (int)header.caplen) {
                if (j % 16 == 0) {
                    printf(" %s\n", asciiprint);
                    memset(asciiprint, '\0', 17);
                    printf("0x%04x ", j);
                }
                if (packet[j] < 33 || packet[j] > 127) {
                    asciiprint[j % 16] = '.';
                }
                else {
                    asciiprint[j % 16] = packet[j];
                }
                printf("%02x ", packet[j]);
                j++;
            }
            printf(" %*s\n\n", (16 - j % 16) * 3 + ((j % 16) ? 1 : 0), asciiprint);

            k++;
        }
    }
    pcap_close(devopen);
    return 0;
}
