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

# Testing
## What was tested
All runs tested:
* How the program handles arguments
* How the program composes the string for the filter
* How the program catches the necessary packages
* And how does she write out information about them
## Why it was tested
On some launches, there was a segmentation fault before, so testing was carried out with different filters to make sure the code worked correctly
## How it was tested/what was the testing environment
The program was tested on linux os and nixOS.
For testing, I used a program that sends packages from this repository:
https://github.com/turytsia/vut-ipk-packegen
I entered the arguments I needed, got the output and checked with expectation
## what were the inputs, expected outputs, and actual outputs
#### Input
sudo ./ipk-sniffer -i eth0 --udp
#### expected outputs, and actual outputs
timestamp: 18:39:01.688101
src MAC: 00:15:5D:10:EB:5E
dst MAC: 01:00:5E:7F:FF:FA
frame length: 216 bytes
src IP: 172.25.64.1
dst IP: 239.255.255.250
src port: 17664
dst port: 202

0x0000 01 00 5e 7f ff fa 00 15 5d 10 eb 5e 08 00 45 00  ..^....]..^..E.
0x0010 00 ca 8c 43 00 00 01 11 50 cb ac 19 40 01 ef ff  ...C....P...@...
0x0020 ff fa cf ec 07 6c 00 b6 47 65 4d 2d 53 45 41 52  .....l..GeM-SEAR
0x0030 43 48 20 2a 20 48 54 54 50 2f 31 2e 31 0d 0a 48  CH.*.HTTP/1.1..H
0x0040 4f 53 54 3a 20 32 33 39 2e 32 35 35 2e 32 35 35  OST:.239.255.255
0x0050 2e 32 35 30 3a 31 39 30 30 0d 0a 4d 41 4e 3a 20  .250:1900..MAN:.
0x0060 22 73 73 64 70 3a 64 69 73 63 6f 76 65 72 22 0d  "ssdp:discover".
0x0070 0a 4d 58 3a 20 31 0d 0a 53 54 3a 20 75 72 6e 3a  .MX:.1..ST:.urn:
0x0080 64 69 61 6c 2d 6d 75 6c 74 69 73 63 72 65 65 6e  dial-multiscreen
0x0090 2d 6f 72 67 3a 73 65 72 76 69 63 65 3a 64 69 61  -org:service:dia
0x00a0 6c 3a 31 0d 0a 55 53 45 52 2d 41 47 45 4e 54 3a  l:1..USER-AGENT:
0x00b0 20 47 6f 6f 67 6c 65 20 43 68 72 6f 6d 65 2f 31  .Google.Chrome/1
0x00c0 31 32 2e 30 2e 35 36 31 35 2e 38 36 20 57 69 6e  12.0.5615.86.Win
0x00d0 64 6f 77 73 0d 0a 0d 0a                   dows....

#### Input
 sudo ./ipk-sniffer -i eth0 -n 5
#### expected outputs, and actual outputs
timestamp: 18:17:21.864034
src MAC: 00:15:5D:10:EB:5E
dst MAC: 01:00:5E:7F:FF:FA
frame length: 179 bytes
src IP: 172.25.64.1
dst IP: 239.255.255.250
src port: 17664
dst port: 165
 
0x0000 01 00 5e 7f ff fa 00 15 5d 10 eb 5e 08 00 45 00  ..^....]..^..E.
0x0010 00 a5 8c 15 00 00 04 11 4e 1e ac 19 40 01 ef ff  ........N...@...
0x0020 ff fa ce c3 07 6c 00 91 5a 69 4d 2d 53 45 41 52  .....l..ZiM-SEAR
0x0030 43 48 20 2a 20 48 54 54 50 2f 31 2e 31 0d 0a 48  CH.*.HTTP/1.1..H
0x0040 6f 73 74 3a 20 32 33 39 2e 32 35 35 2e 32 35 35  ost:.239.255.255
0x0050 2e 32 35 30 3a 31 39 30 30 0d 0a 53 54 3a 20 75  .250:1900..ST:.u
0x0060 72 6e 3a 73 63 68 65 6d 61 73 2d 75 70 6e 70 2d  rn:schemas-upnp-
0x0070 6f 72 67 3a 64 65 76 69 63 65 3a 49 6e 74 65 72  org:device:Inter
0x0080 6e 65 74 47 61 74 65 77 61 79 44 65 76 69 63 65  netGatewayDevice
0x0090 3a 31 0d 0a 4d 61 6e 3a 20 22 73 73 64 70 3a 64  :1..Man:."ssdp:d
0x00a0 69 73 63 6f 76 65 72 22 0d 0a 4d 58 3a 20 33 0d  iscover"..MX:.3.
0x00b0 0a 0d 0a                                       ...

timestamp: 18:17:24.875248
src MAC: 00:15:5D:10:EB:5E
dst MAC: 01:00:5E:7F:FF:FA
frame length: 179 bytes
src IP: 172.25.64.1
dst IP: 239.255.255.250
src port: 17664
dst port: 165

0x0000 01 00 5e 7f ff fa 00 15 5d 10 eb 5e 08 00 45 00  ..^....]..^..E.
0x0010 00 a5 8c 16 00 00 04 11 4e 1d ac 19 40 01 ef ff  ........N...@...
0x0020 ff fa ce c3 07 6c 00 91 5a 69 4d 2d 53 45 41 52  .....l..ZiM-SEAR
0x0030 43 48 20 2a 20 48 54 54 50 2f 31 2e 31 0d 0a 48  CH.*.HTTP/1.1..H
0x0040 6f 73 74 3a 20 32 33 39 2e 32 35 35 2e 32 35 35  ost:.239.255.255
0x0050 2e 32 35 30 3a 31 39 30 30 0d 0a 53 54 3a 20 75  .250:1900..ST:.u
0x0060 72 6e 3a 73 63 68 65 6d 61 73 2d 75 70 6e 70 2d  rn:schemas-upnp-
0x0070 6f 72 67 3a 64 65 76 69 63 65 3a 49 6e 74 65 72  org:device:Inter
0x0080 6e 65 74 47 61 74 65 77 61 79 44 65 76 69 63 65  netGatewayDevice
0x0090 3a 31 0d 0a 4d 61 6e 3a 20 22 73 73 64 70 3a 64  :1..Man:."ssdp:d
0x00a0 69 73 63 6f 76 65 72 22 0d 0a 4d 58 3a 20 33 0d  iscover"..MX:.3.
0x00b0 0a 0d 0a                                       ...

timestamp: 18:17:25.646606
src MAC: 00:15:5D:10:EB:5E
dst MAC: 33:33:00:01:00:02
frame length: 134 bytes
src IP: fe80::aea5:e547:d9b6:31c2
dst IP: ff02::1:2
src port: 546
dst port: 547

0x0000 33 33 00 01 00 02 00 15 5d 10 eb 5e 86 dd 60 08  33......]..^..`.
0x0010 cc c1 00 50 11 01 fe 80 00 00 00 00 00 00 ae a5  ...P............
0x0020 e5 47 d9 b6 31 c2 ff 02 00 00 00 00 00 00 00 00  .G..1...........
0x0030 00 00 00 01 00 02 02 22 02 23 00 50 4a 77 01 6a  .......".#.PJw.j
0x0040 40 cc 00 08 00 02 0c 22 00 01 00 0e 00 01 00 01  @......"........
0x0050 28 f7 33 8d 28 cd c4 a0 47 1d 00 03 00 0c 3b 00  (.3.(...G.....;.
0x0060 15 5d 00 00 00 00 00 00 00 00 00 10 00 0e 00 00  .]..............
0x0070 01 37 00 08 4d 53 46 54 20 35 2e 30 00 06 00 06  .7..MSFT.5.0....
0x0080 00 11 00 17 00 18                           ......

timestamp: 18:17:27.885024
src MAC: 00:15:5D:10:EB:5E
dst MAC: 01:00:5E:7F:FF:FA
frame length: 179 bytes
src IP: 172.25.64.1
dst IP: 239.255.255.250
src port: 17664
dst port: 165

0x0000 01 00 5e 7f ff fa 00 15 5d 10 eb 5e 08 00 45 00  ..^....]..^..E.
0x0010 00 a5 8c 17 00 00 04 11 4e 1c ac 19 40 01 ef ff  ........N...@...
0x0020 ff fa ce c3 07 6c 00 91 5a 69 4d 2d 53 45 41 52  .....l..ZiM-SEAR
0x0030 43 48 20 2a 20 48 54 54 50 2f 31 2e 31 0d 0a 48  CH.*.HTTP/1.1..H
0x0040 6f 73 74 3a 20 32 33 39 2e 32 35 35 2e 32 35 35  ost:.239.255.255
0x0050 2e 32 35 30 3a 31 39 30 30 0d 0a 53 54 3a 20 75  .250:1900..ST:.u
0x0060 72 6e 3a 73 63 68 65 6d 61 73 2d 75 70 6e 70 2d  rn:schemas-upnp-
0x0070 6f 72 67 3a 64 65 76 69 63 65 3a 49 6e 74 65 72  org:device:Inter
0x0080 6e 65 74 47 61 74 65 77 61 79 44 65 76 69 63 65  netGatewayDevice
0x0090 3a 31 0d 0a 4d 61 6e 3a 20 22 73 73 64 70 3a 64  :1..Man:."ssdp:d
0x00a0 69 73 63 6f 76 65 72 22 0d 0a 4d 58 3a 20 33 0d  iscover"..MX:.3.
0x00b0 0a 0d 0a                                       ...

timestamp: 18:17:30.904490
src MAC: 00:15:5D:10:EB:5E
dst MAC: 01:00:5E:7F:FF:FA
frame length: 179 bytes
src IP: 172.25.64.1
dst IP: 239.255.255.250
src port: 17664
dst port: 165

0x0000 01 00 5e 7f ff fa 00 15 5d 10 eb 5e 08 00 45 00  ..^....]..^..E.
0x0010 00 a5 8c 18 00 00 04 11 4e 1b ac 19 40 01 ef ff  ........N...@...
0x0020 ff fa ce c3 07 6c 00 91 5a 69 4d 2d 53 45 41 52  .....l..ZiM-SEAR
0x0030 43 48 20 2a 20 48 54 54 50 2f 31 2e 31 0d 0a 48  CH.*.HTTP/1.1..H
0x0040 6f 73 74 3a 20 32 33 39 2e 32 35 35 2e 32 35 35  ost:.239.255.255
0x0050 2e 32 35 30 3a 31 39 30 30 0d 0a 53 54 3a 20 75  .250:1900..ST:.u
0x0060 72 6e 3a 73 63 68 65 6d 61 73 2d 75 70 6e 70 2d  rn:schemas-upnp-
0x0070 6f 72 67 3a 64 65 76 69 63 65 3a 49 6e 74 65 72  org:device:Inter
0x0080 6e 65 74 47 61 74 65 77 61 79 44 65 76 69 63 65  netGatewayDevice
0x0090 3a 31 0d 0a 4d 61 6e 3a 20 22 73 73 64 70 3a 64  :1..Man:."ssdp:d
0x00a0 69 73 63 6f 76 65 72 22 0d 0a 4d 58 3a 20 33 0d  iscover"..MX:.3.
0x00b0 0a 0d 0a                                       ...

#### And ect.

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