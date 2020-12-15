#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <string.h>


struct network_flow
{
	char* ip_src;
	char* ip_dst;
	unsigned short port_src;
	unsigned short port_dst;
	uint8_t protocol;
	unsigned int last_acknowledgment; // used to discover retransmissions
};

struct network_flow* network_flows_array;
int num_network_flows;
int num_packets_received;
int num_tcp_packets_received;
int num_udp_packets_received;
int num_tcp_bytes_received;
int num_udp_bytes_received;

void usage(void)
{
	printf(
			"\n"
			"usage:\n"
			"\t./monitor \n"
			"Options:\n"
			"-i <interface name>, Monitors network from interface and prints statistics\n"
			"-r <filename>, Monitors network from .pcap file and prints statistics\n"
			"-h, Help message\n\n"
			);

	exit(1);
}


void packet_handler( u_char* args , const struct pcap_pkthdr* packet_header, const u_char *packet_body )
{
	// 3. Decode each received packet
	/***************** Ethernet Protocol *****************/
	struct ether_header* eth_header;
    eth_header = (struct ether_header*) packet_body;


	/***************** Internet Protocol *****************/
	// different headers for ipv4 & ipv6
	struct ip* ip_header = (struct ip*) ( packet_body + sizeof( struct ether_header ) );
	struct ip6_hdr* ip6_header = (struct ip6_hdr*) ( packet_body + sizeof( struct ether_header ) );
	
	int ip_header_length; // in 4 byte words
	uint8_t packet_type;

	if( ip_header->ip_v == 4 ) // IPv4
	{
		ip_header_length = ip_header->ip_hl;
		packet_type = ip_header->ip_p;
	}
	else if( ip_header->ip_v == 6 ) // IPv6
	{
		ip_header_length = 10; // ipv6 has static size
		packet_type = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt; // next header protocol
	}
	
	// 4. Skip any packet that is not TCP or UDP
	if( packet_type != IPPROTO_TCP && packet_type != IPPROTO_UDP )
	{
		num_packets_received++;
		return;
	}

	// IP to human readable form
	int af = ( ip_header->ip_v == 4 ) ? AF_INET : AF_INET6;
	char ip_src_string[INET6_ADDRSTRLEN];
	char ip_dst_string[INET6_ADDRSTRLEN]; // INET6_ADDRSTRLEN > INET_ADDRSTRLEN. Need to serve both cases
	inet_ntop( af , &(ip_header->ip_src) , ip_src_string , sizeof(ip_src_string) );
	inet_ntop( af , &(ip_header->ip_dst) , ip_dst_string , sizeof(ip_dst_string) );


	/***************** TCP/UDP Protocol *****************/
	// tcp/udp headers
	struct tcphdr* tcp_header = (struct tcphdr*) ( (__u32*) ip_header + ip_header_length );
	struct udphdr* udp_header = (struct udphdr*) ( (__u32*) ip_header + ip_header_length );

	unsigned short port_src;
	unsigned short port_dst;
	unsigned int protocol_header_length;

	if( packet_type == IPPROTO_TCP )
	{
		port_src = ntohs( tcp_header->source ); // convert from network byte order to host byte order.
		port_dst = ntohs( tcp_header->dest );
		protocol_header_length = tcp_header->doff * 4; // doff is header length in 4-byte word. 
	}
	else if( packet_type == IPPROTO_UDP )
	{
		port_src = ntohs( udp_header->source );
		port_dst = ntohs( udp_header->dest );
		protocol_header_length = 8;
	}

	/******************** Payload ********************/
	unsigned int payload_length = packet_header->len - sizeof( struct ether_header ) - ip_header_length - protocol_header_length;
	

	/*************** Print packet info ***************/
	// 5. Print the packet’s source and destination IP addresses
	printf(
		"Source IP:		%s\n"
		"Dest. IP:		%s\n"
		, ip_src_string , ip_dst_string
		);

	// 6. Print the packet’s source and destination port numbers
	printf(
		"Source port:		%hu\n"
		"Dest. port:		%hu\n"
		, port_src , port_dst
		);

	// 7. Print the packet’s protocol.
	printf( "Protocol:		%s\n" , ( packet_type == IPPROTO_TCP ) ? "TCP" : "UDP" );

	// 8. Print the packet’s TCP/UDP header length and TCP/UDP payload length in bytes.
	printf(
		"Protocol header length:	%d\n"
		"Payload length:		%d\n\n"
		, protocol_header_length , payload_length
		);


	/**************** Network Flows *****************/
	// first packet, array is empty
	if( network_flows_array == NULL )
	{
		network_flows_array = (struct network_flow*) malloc( sizeof( struct network_flow ) );
		network_flows_array[0].ip_src = (char*) malloc( ( ip_header->ip_v == 4 ) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN );
		network_flows_array[0].ip_dst = (char*) malloc( ( ip_header->ip_v == 4 ) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN );

		strcpy( network_flows_array[0].ip_src , ip_src_string );
		strcpy( network_flows_array[0].ip_dst , ip_dst_string );

		network_flows_array[0].port_src = port_src;
		network_flows_array[0].port_dst = port_dst;

		network_flows_array[0].protocol = packet_type;
	}
	else // na tsekarei oti den ksanauparxei
	{
		network_flows_array = realloc( network_flows_array , ( num_packets_received + 1 ) * sizeof( struct network_flow ) ); // prepei na allaksei to num_packets_received se num tuples
		network_flows_array[num_packets_received].ip_src = (char*) malloc( ( ip_header->ip_v == 4 ) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN );
		network_flows_array[num_packets_received].ip_dst = (char*) malloc( ( ip_header->ip_v == 4 ) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN );

		strcpy( network_flows_array[num_packets_received].ip_src , ip_src_string );
		strcpy( network_flows_array[num_packets_received].ip_dst , ip_dst_string );

		network_flows_array[num_packets_received].port_src = port_src;
		network_flows_array[num_packets_received].port_dst = port_dst;

		network_flows_array[num_packets_received].protocol = packet_type;
	}

	/**************** Retransmission ****************/


	
	
	/****************** Keep Stats ******************/
	num_packets_received++;

	if(packet_type == IPPROTO_TCP)
	{
		num_tcp_packets_received++;
		num_tcp_bytes_received += protocol_header_length + payload_length;
	}
	else // udp
	{
		num_udp_packets_received++;
		num_udp_bytes_received += protocol_header_length + payload_length;
	}
	
	
}


int main( int argc , char* argv[] )
{
	int ch;

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout_limit = 10000; /* In milliseconds */

	if (argc != 3 )
		usage();

	// 1. Select interface or pcap file
	while ( ( ch = getopt( argc , argv , "hir:" ) ) != -1 )
	{
		switch (ch)
		{		
		case 'i':
			// network interface
			handle = pcap_open_live( argv[2] , BUFSIZ , 0 , timeout_limit , error_buffer );
			break;
		case 'r':
			// pcap file
			handle = pcap_open_offline( argv[2] , error_buffer );
			break;
		default:
			usage();
		}
	}
	network_flows_array = NULL;
	num_network_flows = 0;
	num_packets_received = 0;
	num_tcp_packets_received = 0;
	num_udp_packets_received = 0;
	num_tcp_bytes_received = 0;
	num_udp_bytes_received = 0;
	// 2. Start capturing/reading packets
    pcap_loop( handle , 0 , packet_handler , NULL );

printf("\n\n");
	for( int i = 0 ; i < num_packets_received ; i++ )
	{
		printf("%s\n" , network_flows_array[i].ip_src );
		printf("%s\n" , network_flows_array[i].ip_dst );

		printf("%hu\n" , network_flows_array[i].port_src );
		printf("%hu\n" , network_flows_array[i].port_dst );

		printf("%s\n\n" , ( network_flows_array[i].protocol == IPPROTO_TCP ) ? "TCP" : "UDP" );
	}
printf("\n\n");
	// 12. Print statistics
	// a.
	// b.
	// c.
	// d.
	printf( "Total number of packets received:	%d\n" , num_packets_received) ;
	// e.
	printf( "Total number of TCP packets received:	%d\n" , num_tcp_packets_received );
	// f.
	printf( "Total number of UDP packets received:	%d\n" , num_udp_packets_received );
	// g.
	printf( "Total number of TCP bytes received:	%d\n" , num_tcp_bytes_received );
	// h.
	printf( "Total number of UDP bytes received:	%d\n" , num_udp_bytes_received );

	// clean-up
}