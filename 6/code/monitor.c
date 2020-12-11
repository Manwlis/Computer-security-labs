#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>


// apo8hkeumena network flows ?

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


void packet_handler( u_char *args , const struct pcap_pkthdr *packet_header, const u_char *packet_body )
{
	// Ethernet header
	struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet_body;
	
	if ( ntohs(eth_header->ether_type) == ETHERTYPE_IP )
        ; // Me endiaferei auto?
	

	// 3. Decode each received packet
	struct ip *ip_header = (struct ip*) ( packet_body + sizeof( struct ether_header ) ); // diaforetiko gia ipv4 kai ipv6
	int ip_header_length;
	uint8_t packet_type;

	if( ip_header->ip_v == 4 ) // IPv4
	{
		ip_header_length = ip_header->ip_hl * 4; // The IHL is a 4-byte word. Pointer arithmetic
		packet_type = ip_header->ip_p;
		//printf("IPv4	");
	}
	else if( ip_header->ip_v == 6 ) // IPv6
	{
		struct ip6_hdr *ip6_header = (struct ip6_hdr*) ( packet_body + sizeof( struct ether_header ) );
		ip_header_length = 40; // ipv6 has static size
		packet_type = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt; // next header protocol
		//printf("IPv6	");
	}
	else // something went wrong
		return;
	
	// 4. Skip any packet that is not TCP or UDP
	if( packet_type != IPPROTO_TCP && packet_type != IPPROTO_UDP )
		return;
	//printf("%d\n" , packet_type );

	if( packet_type == IPPROTO_TCP )
	{

	}
	else if( packet_type == IPPROTO_UDP )
	{
		
	}
}


int main( int argc , char *argv[] )
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

	// 2. Start capturing/reading packets
    pcap_loop( handle , 0 , packet_handler , NULL );


	// 12. Print statistics

	// frees
}