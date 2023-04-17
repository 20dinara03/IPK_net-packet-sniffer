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

/**
 * This function prints the names of all available network interfaces.
 * @return 0 if successful, 1 if an error occurs
*/
int print_interfaces()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_if_t *interfaces, *device;

        // retrieve the list of network interfaces
    
        if (pcap_findalldevs(&interfaces, error_buffer) == -1) 
        {
            printf("Error in pcap_findalldevs(): %s", error_buffer);
            return 1;
        }
        
        // print the names of the network interfaces

        for (device = interfaces; device != NULL; device = device->next) {
            printf("%s\n", device->name);
        }

        // free the memory allocated by the list of network interfaces

        pcap_freealldevs(interfaces);
        return 0;
}

/**
 * Parses command-line arguments and stores them in a struct ProgramArgs.
 * @param argc The number of arguments passed to the program.
 * @param argv An array of strings representing the arguments passed to the program.
 * @param args A pointer to a struct ProgramArgs where the parsed arguments will be stored.
 * @return 0 on success, 1 on failure.
*/

int parsing_args(int argc, char *argv[], struct ProgramArgs *args)
{
    // Check if the number of arguments is less than 3 and the first argument is not -h or --help

    if (argc < 3 && strcmp(argv[1], "-h") != 0 && strcmp(argv[1], "--help") != 0)
    {
        // Check if the first argument is not -i or --interface
        if (strcmp(argv[1], "-i") != 0 && strcmp(argv[1], "--interface") != 0)
        {
            printf("Network interfaces not found.\n");
            printf("Usage:\n");
            printf("./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
            return 1;
        }
        else{print_interfaces(); exit(0);}
    }
    // Check if the first argument is -h or --help
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
    // Initializes a variable i to 1 for argument processing.
    int i = 1;
    // Processes all command-line arguments.
    while (i < argc)
    {
        // Checks if the argument is "--tcp" or "-t" and sets the corresponding flag in the struct to true.
        if (strcmp(argv[i], "--tcp") == 0 || strcmp(argv[i], "-t") == 0) 
        {
            // If the flag is already set, it calls the Error() function.
            if (args->tcp){Error();}
            args->tcp = true;
        }
        // Checks if the argument is "--udp" or "-u" and sets the corresponding flag in the struct to true.
        else if (strcmp(argv[i], "--udp") == 0 || strcmp(argv[i], "-u") == 0) 
        {
            // If the flag is already set, it calls the Error() function.
            if (args->udp){Error();}
            args->udp = true;
        }
        // Checks if the argument is "--arp" and sets the corresponding flag in the struct to true.
        else if (strcmp(argv[i], "--arp") == 0) 
        {
            // If the flag is already set, it calls the Error() function.
            if (args->arp){Error();}
            args->arp = true;
        }
        // Checks if the argument is "--icmp4" and sets the corresponding flag in the struct to true.
        else if (strcmp(argv[i], "--icmp4") == 0) 
        {
            if (args->icmp4){Error();}
            args->icmp4 = true;
        }
        // Checks if the argument is "--icmp6" and sets the corresponding flag in the struct to true.
        else if (strcmp(argv[i], "--icmp6") == 0) 
        {
            if (args->icmp6){Error();}
            args->icmp6 = true;
        }
        // Checks if the argument is "--igmp" and sets the corresponding flag in the struct to true.
        else if (strcmp(argv[i], "--igmp") == 0) 
        {
            if (args->igmp){Error();}
            args->igmp = true;
        }
        // Checks if the argument is "--mld" and sets the corresponding flag in the struct to true.
        else if (strcmp(argv[i], "--mld") == 0) 
        {
            if (args->mld){Error();}
            args->mld = true;
        }
        // Checks if the argument is "--ndp" and sets the corresponding flag in the struct to true.
        else if (strcmp(argv[i], "--ndp") == 0) 
        {
            if (args->ndp){Error();}
            args->ndp = true;
        }
        // Checks if the argument is "-i" and sets the interface name in the struct.
        // If the next argument is not a flag, it sets the interface name to the next argument.
        else if (strcmp(argv[i], "-i") == 0) 
        {
            if ((i+1) < argc)
            {
                if (argv[i+1][0] != '-')
                {
                    strcpy(args->interface, argv[i+1]);
                    i++;
                }
                // If the next argument is a flag, it sets the interface name to an empty string.
                else{args->interface = "";}
            }
        }
        // If the -n argument is passed, it checks that it hasn't already been set and that a valid number has been provided.
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
        // If the -p argument is passed, it checks that it hasn't already been set and that a valid port number has been provided.
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
        // If an unknown argument is passed, it prints an error message and returns 1.
        else
        {
            printf("Unknown program argument\n");
            return 1;
        }
        i++;
    }
    // If no interface is specified, it prints the available interfaces and exits.
    if (strlen(args->interface) == 0){print_interfaces();exit(0);}
    // It returns 0 if all arguments have been successfully parsed.
    return 0;
}

/**
* @brief capture packets from a network interface, based on user-specified protocols and filters
* @param args pointer to ProgramArgs struct containing user-specified command line arguments
* @return pointer to a pcap_t struct, which can be used to capture packets from the specified network interface
*/
pcap_t* work_with_device(struct ProgramArgs *args)
{
    // declare variables
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32  device_ip, netmask;
    struct bpf_program fp;
    char filter_exp[100] = {'\0'};

    // get the device IP and netmask
    if (pcap_lookupnet(args->interface, &device_ip, &netmask, errbuf) == -1)
    {
        printf("Error with  ip and netmask of device: %s\n", errbuf);
        return NULL;
    }
    // open the device for capturing
    devopen = pcap_open_live(args->interface, BUFSIZ, 1, 1000, errbuf);
    if (devopen == NULL)
    {
        printf("Error with  openning device: %s\n", errbuf);
        return NULL;
    }
    // check if the device provides Ethernet headers
    if(pcap_datalink(devopen) != DLT_EN10MB)
    {
        printf("Interface does not provide Ethernet headers");
        return NULL;
    }
    // set defaults for which protocols to capture
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
     // set the filter expression based on which protocols to capture

     // If both TCP and UDP protocols are selected and a port is specified,
     // set the filter to capture packets for the specified port on both protocols.
    if (args->tcp && args->udp) 
    {
        // If a port is not specified, set the filter to capture all ports on both protocols.
        if (args->port == -1) {sprintf(filter_exp, "(tcp and portrange 0-65535) or (udp and portrange 0-65535)");} 
        else {sprintf(filter_exp, "(tcp and port %d) or (udp and port %d)", args->port, args->port); }
    } 
     // If only TCP protocol is selected and a port is specified,
     // set the filter to capture packets for the specified port on TCP.
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
    // If ARP protocol is selected, add ARP to the filter expression.
    if (args->arp) 
    {
        if (filter_exp[0] == '\0') {sprintf(filter_exp, "arp");}
        else {strcat(filter_exp, " or arp");}
    }
    // If IGMP protocol is selected, add IGMP to the filter expression.
    if (args->igmp) 
    {
        if (filter_exp[0] == '\0') {sprintf(filter_exp, "igmp");}
        else {strcat(filter_exp, " or igmp");}
    }
    // If MLD protocol is selected, add ICMPv6 MLD to the filter expression.
    if (args->mld) {
        if (filter_exp[0] == '\0') { sprintf(filter_exp, "(icmp6 and (icmp6[0] >= 130 and icmp6[0] <= 132))"); }
        else { strcat(filter_exp, " or (icmp6 and (icmp6[0] >= 130 and icmp6[0] <= 132))"); }
    }
    if (args->ndp) {
        if (filter_exp[0] == '\0') { sprintf(filter_exp, "(icmp6 and (icmp6[0] >= 133 and icmp6[0] <= 137))"); }
        else { strcat(filter_exp, " or (icmp6 and (icmp6[0] >= 133 and icmp6[0] <= 137))"); }
    }
    // If ICMPv4 protocol is selected, add ICMPv4 to the filter expression.
    if (args->icmp4) 
    {
        if (filter_exp[0] == '\0') {sprintf(filter_exp, "icmp");} 
        else {strcat(filter_exp, " or icmp");}
    }
    // Set the filter expression to capture ICMPv6 packets if args->icmp6 is true
    if (args->icmp6) 
    {
        if (filter_exp[0] == '\0') {sprintf(filter_exp, "icmp6");} 
        // Otherwise, append "or icmp6" to the existing filter expression
        else {strcat(filter_exp, " or icmp6");}
    }
    // Compile the filter expression into a filter program and apply it to the device
    if(pcap_compile(devopen, &fp, filter_exp, 0, device_ip) == -1) 
    {
        // Print an error message and return NULL if compilation fails
        printf("Error: compile failed (%s)\n", pcap_geterr(devopen));
        return NULL;
    }
    // Set the compiled filter program on the device
    if(pcap_setfilter(devopen, &fp) == -1)
	{
        // Print an error message and return NULL if setting the filter fails
		printf("Error: setting filter failed (%s)\n", pcap_geterr(devopen));
		return NULL;
	}
    // Return the device handle
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
            // Get next packet from device
            packet = pcap_next(devopen, &header);
            struct ether_header* ethernet;
            ethernet = (struct ether_header*)(packet);
            char src_ip[100] = {'\0'};
            char dst_ip[100] = {'\0'};
            char src_ip6[100] = {'\0'};
            char dst_ip6[100] = {'\0'};
            char time[100] = {'\0'};
            // Format timestamp string
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
            // Check if Ethernet packet contains an IP packet.
            if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
                // Extract the IP header from the packet.
                struct ip* ipHeader;
                ipHeader = (struct ip*)(packet + 14);
                // Print source and destination IP addresses
                inet_ntop(AF_INET, &ipHeader->ip_src, src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &ipHeader->ip_dst, dst_ip, INET_ADDRSTRLEN);
                printf("src IP: %s\n", src_ip);
                printf("dst IP: %s\n", dst_ip);
                // Check if the IP packet is a TCP packet.
                if (ipHeader->ip_p == IPPROTO_TCP) {
                    // Extract the TCP header from the packet.
                    struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14);
                    printf("src port: %d\n", ntohs(tcp_header->th_sport));
                    printf("dst port: %d\n", ntohs(tcp_header->th_dport));
                }
                // Check if the IP packet is a UDP packet.
                else if (ipHeader->ip_p == IPPROTO_UDP) {
                    // Extract the UDP header from the packet.
                    struct udphdr* udp_header = (struct udphdr*)(packet + 14);
                    printf("src port: %d\n", ntohs(udp_header->uh_sport));
                    printf("dst port: %d\n", ntohs(udp_header->uh_dport));
                }
                // else if (ipHeader->ip_p == 1) {
                //     struct icmphdr* icmp_header = (struct icmphdr*)(packet + 14);
                // }
            }
            // Check if Ethernet packet contains an ARP packet.
            else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
                // Extract the ARP header from the packet.
                struct ether_arp* arp_header = (struct ether_arp*)(packet + 14);
                // Print source and destination IP addresses.
                char arpbuf1[100] = { '\0' };
                char arpbuf2[100] = { '\0' };
                printf("src IP: %s\n", inet_ntop(AF_INET, arp_header->arp_spa, arpbuf1, 100));
                printf("dst IP: %s\n", inet_ntop(AF_INET, arp_header->arp_tpa, arpbuf2, 100));
            }
            // Check if Ethernet packet contains an IPv6 packet.
            else if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV6) {
                // Extract the IPv6 header from the packet.
                struct ip6_hdr* ip6_header = (struct ip6_hdr*)(packet + 14);
                // Print source and destination IP addresses.
                inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip6, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip6, INET6_ADDRSTRLEN);
                printf("src IP: %s\n", src_ip6);
                printf("dst IP: %s\n", dst_ip6);
                // Check the protocol type of the IPv6 header, if it's TCP or UDP, extract the corresponding header information and print the source and destination ports.
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
            // Print the hexadecimal and ASCII representation of the packet.
            char asciiprint[17] = { '\0' };
            int j = 0;
            while (j < (int)header.caplen) {
                // Print a new line every 16 bytes.
                if (j % 16 == 0) {
                    printf(" %s\n", asciiprint);
                    memset(asciiprint, '\0', 17);
                    printf("0x%04x ", j);
                }
                // If the byte is not printable ASCII, replace it with a dot.
                if (packet[j] < 33 || packet[j] > 127) {
                    asciiprint[j % 16] = '.';
                }
                else {
                    asciiprint[j % 16] = packet[j];
                }
                // Print the hexadecimal value of the current byte.
                printf("%02x ", packet[j]);
                j++;
            }
            // Print the last line of ASCII representation, padding with spaces as necessary.
            printf(" %*s\n\n", (16 - j % 16) * 3 + ((j % 16) ? 1 : 0), asciiprint);

            k++;
        }
    }
    // Close the device and return 0 to indicate successful completion.
    pcap_close(devopen);
    return 0;
}
