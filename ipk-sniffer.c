#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include<pcap/pcap.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<netinet/ether.h>
#include<netinet/ip6.h>
#include<netinet/tcp.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include <netinet/ip.h>
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
        else{print_interfaces();}
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

    if (strlen(args->interface) == 0){print_interfaces();}
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
    printf("%s\n", filter_exp);
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
    if (devopen != NULL)
    {
    //    if(pcap_loop(devopen, args.number, parse_packet, NULL))
    //    {
    //     return 1;
    //    }
    }
    printf("OK!\n");
    return 0;
}