# README
## IPK project 2
author: **Dinara Garipova** (xgarip00)  
date: **2023-03-21**
Gitea profile: [xgarip00](https://git.fit.vutbr.cz/xgarip00)

# Task:
## Packet Sniffer
This is a C program for a simple packet sniffer that can capture and display network traffic. The program uses the pcap library to capture packets and parse them. It takes command-line arguments to filter packets based on various criteria such as protocol type, interface, port, etc.



The main function of this program is to parse command-line arguments, set up the filter based on the user's specifications, and start capturing packets. When a packet is captured, it is analyzed to determine its protocol type and other information, which is then displayed on the console.

## Usage
```bash
Usage: ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
```
* -i [string]   specify an interface
* -n [integer]  set packet limit (unlimited if not set)
* -p [integer]  set packet port to filter
* -u            filter only UDP packets
* -t            filter only TCP packets

# Requirements
To compile and run this code, you need:

* C compiler (GCC or Clang)
* Linux/Unix system (Ubuntu, Debian, Fedora, macOS)
* Basic knowledge of C programming

## Compilation
This project can be compiled using Makefile:
```bash
make
```
## Compatibility
File can be compiled at 3 different platforms:
* Linux
* Windows **_(not supported)_**
* MacOS


# Implementation
## Content structuring
The program first includes various header files for the libraries and functions it uses. The ProgramArgs structure is defined to store the user's command-line arguments.

The print_interfaces function uses the pcap_findalldevs function from the pcap library to obtain a list of network interfaces on the system and prints them to the console.

The parsing_args function parses the command-line arguments and stores them in the ProgramArgs structure. It checks for various options such as -h or --help for displaying help, -i or --interface for specifying the network interface, -n for setting the packet limit, -p for setting the port number to filter, and various other options for filtering packets based on their protocol type.

The main function first initializes the ProgramArgs structure with default values and calls the parsing_args function to parse the command-line arguments. It then calls the pcap_open_live function from the pcap library to open the specified network interface for capturing packets.

In a loop that runs args.number times, it uses the pcap_next function to get the next packet from the network interface devopen and stores it in the packet variable.
It then extracts the Ethernet header from the packet and prints the source and destination MAC addresses and the frame length.
If the packet is an IPv4 packet, it extracts the IPv4 header from the packet and prints the source and destination IP addresses and the source and destination port numbers (if the packet is TCP or UDP).
If the packet is an ARP packet, it extracts the ARP header from the packet and prints the source and destination IP addresses.
If the packet is an IPv6 packet, it extracts the IPv6 header from the packet and prints the source and destination IP addresses and the source and destination port numbers (if the packet is TCP or UDP).
It then prints a hexadecimal dump of the packet data, 16 bytes per line, with ASCII representation on the right.

## Required libraries
* <string.h> - strcpy(), strcat()
* <stdio.h> - printf()
* <stdlib.h>
* <stdbool.h> - type boolean
* <unistd.h>
* <time.h> - time(), time miliseconds
* <pcap/pcap.h> - access to library functions (etc. pcap_lookupdev())
* <arpa/inet.h> - inet_ntop()

Network Data Structures:
* <netinet/if_ether.h>
* <netinet/ether.h>
* <netinet/ip6.h>
* <netinet/tcp.h>
* <netinet/ip.h>
* <netinet/ip_icmp.h>
* <netinet/udp.h>
* <netinet/in.h>
* <net/ethernet.h>
* <netinet/icmp6.h>

## Functions
### int print_interfaces()
 This function prints the names of all available network interfaces.
 @return 0 if successful, 1 if an error occurs
### int parsing_args(int argc, char *argv[], struct ProgramArgs *args)
Parses command-line arguments and stores them in a struct ProgramArgs.
 @param argc The number of arguments passed to the program.
 @param argv An array of strings representing the arguments passed to the program.
 @param args A pointer to a struct ProgramArgs where the parsed arguments will be stored.
 @return 0 on success, 1 on failure.
### pcap_t* work_with_device(struct ProgramArgs *args)
 @brief capture packets from a network interface, based on user-specified protocols and filters
 @param args pointer to ProgramArgs struct containing user-specified command line arguments
 @return pointer to a pcap_t struct, which can be used to capture packets from the specified network interface
### main(int argc, const char * argv[])
 Description: The main function for the client program Parameters:
 argc - the number of arguments passed to the program
 argv - an array of strings containing the arguments passed to the program Returns: int (0 if successful)

 ## Global Variables
 ### pcap_t* devopen
 A pointer named devopen of type pcap_t. This is likely to be used for opening and reading packets from a network device using the libpcap library.

# Sequence Diagram
   * participant User
   * participant Main
   * participant Parsing_args
   * participant Print_interfaces
   * participant Error
   * participant Work_with_device
   
   ```mermaid
   sequenceDiagram
     User->>Main: Starts the program with input arguments
     activate Main
     Main->>Parsing_args: Checking Program Input Arguments
     Parsing_args->>Error: Throwing an error on invalid arguments
     Parsing_args->>Print_interfaces: If only the interface filter is specified in the arguments
     activate Print_interfaces
     Print_interfaces->>Main: Write out all possible interfaces
     deactivate Print_interfaces

     Main->>Work_with_device: Opening and working with devices

     loop send/recv
         Main->>User: Write out information about each package
     end

     Main->>User: Closes the device
     deactivate Main
   ```


# Bibliography
* [PROGRAMMING WITH PCAP](https://www.tcpdump.org/pcap.html)
* [Sniffer example of TCP/IP packet capture using libpcap](https://www.tcpdump.org/other/sniffex.c)
* [Parsing arguments](https://stackoverflow.com/questions/9642732/parsing-command-line-arguments-in-c)
* [Example sniffer](https://eax.me/libpcap/)

# Theory
## What is sniffer
A sniffer is a program or device that allows you to monitor and analyze network traffic at the packet level. Using a sniffer, you can capture and analyze network packets that are transmitted over the network between devices and obtain information about the transmitted data.

Sniffers are used for various purposes such as analyzing network traffic, detecting security breaches, debugging and testing networks.

Sniffers work at the network interface level. They can be implemented as software on a computer or as a physical device connected to a network interface.

Software sniffers work like this:

Packet Capture: The sniffer captures network packets that are sent over the network between devices.

Packet sniffing: The sniffer parses captured packets and extracts information from packet headers such as destination and send IP addresses and ports, protocol types, sequence numbers, and more.

Data display: The sniffer displays the information obtained from the captured packets in a user-friendly way, such as a table or graph.

Data Filtering: The sniffer can filter captured packets based on various criteria such as IP address, port, or protocol type to display only the data that is important to the user.

## How working pcap functions
The pcap functions provide the programmer with the ability to capture, filter, parse, and process packets transmitted over the network. With pcap, you can implement various sniffer functions, such as:

Packet capturing: pcap_open_live() - Opens a network interface for capturing packets.

Packet filtering: pcap_compile() and pcap_setfilter() - compile and set a filter for captured packets.

Packet handling: pcap_dispatch() - Processes captured packets in real time.

Saving packets: pcap_dump_open() and pcap_dump() - save captured packets to a file.

Packet analysis: pcap_next() and pcap_next_ex() - return the next captured packet for analysis.

Close session: pcap_close() Closes a packet capture session.