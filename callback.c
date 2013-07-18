/********************************************
	This is the callback function
**********************************************/

#include"sniff.h"
#define SID_SNIFF_SER_MAX_LEN 50

void packet_found(u_char *filename,const struct pcap_pkthdr *header,const u_char *packet)
{
 int i;
 static count = 0;
 FILE *here;			//the data stream
 struct ether_header *eth_hdr;	// net/ethernet.h
 if(!filename)			//no filename provided
  here = stdout;
 else
 {
  if(count == 0)			//opening file first time
   printf("Opening file ... %s\n",filename);
  here = fopen(filename,"a");	//append in that file
  if(here == NULL)
  {
   fprintf(stderr,"ERROR: The log file can not be created !!\n");
   printf("Changing stream to output ...\n"); 
   here = stdout;
  }
  printf("Writting packet information to the file ...\n");
 }
 fprintf(here,"\n\npacket no %d:\n",count++);

 /***********************************************************
 	packet's information:
 
   struct pcap_pkthdr {
	struct timeval ts;
	bpf_u_int32 caplen;
	bpf_u_int32 len;
	};
 ************************************************************/ 
 fprintf(here,"\nPacket Captured:\n");
 fprintf(here,"Total length of packet avilable = %d\n",header->len);
 fprintf(here,"Total length captured = %d\n",header->caplen);
 
/************************************************************ 
	printing information inside the packet
	 assuming ETHERNET interface:

This is a name for the 48 bit ethernet address available on many
   systems.  
struct ether_addr
{
  u_int8_t ether_addr_octet[ETH_ALEN];
} __attribute__ ((__packed__));

10Mb/s ethernet header 
struct ether_header
{
  u_int8_t  ether_dhost[ETH_ALEN];       destination eth addr 
  u_int8_t  ether_shost[ETH_ALEN];       source ether addr   
  u_int16_t ether_type;                  packet type ID field 
} __attribute__ ((__packed__));

 Ethernet protocol ID's 
#define ETHERTYPE_PUP           0x0200           Xerox PUP 
#define ETHERTYPE_IP            0x0800           IP 
#define ETHERTYPE_ARP           0x0806           Address resolution 
#define ETHERTYPE_REVARP        0x8035           Reverse ARP 
****************************************************************/
	/***************************************************************
		Prototype of ether_ntoa:

	convert MAC Address to human readable:
	extern char *ether_ntoa(__const ether_addr *__addr) __THROW;
 	***************************************************************/
 eth_hdr = (struct ether_header *)packet;
 fprintf(here,"\nPrinting the Ethernet information:\n");
 fprintf(here,"Source Address: %s\n",ether_ntoa(eth_hdr->ether_shost));
 fprintf(here,"Destination Address: %s\n",ether_ntoa(eth_hdr->ether_dhost));
 fprintf(here,"Packet Type: ");
#undef ETHERTYPE_IP		//i don't know why, but the orignals at <netinet/if_ether.h> are not working for me
#define ETHERTYPE_IP 0x0008 
#undef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0608
#undef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP 0x3580	//just reversing the bit-order, hope it works :(
 switch(eth_hdr->ether_type)
 {
/* i'm not sure 'bout Xerox PUP
  case ETHERTYPE_PUP:
  	printf("Xerox PUP\n");
	break;
*/
  case ETHERTYPE_IP:
	fprintf(here,"IP\n");
	its_ip(header->len,packet,here,sizeof(struct ether_header));
	break;
  case ETHERTYPE_ARP:
	fprintf(here,"ARP\n");
   	its_arp(header->len,packet,here,sizeof(struct ether_header));
	break;
  case ETHERTYPE_REVARP:
	fprintf(here,"Reverse ARP\n");
	break;
  default:
	fprintf(here,"Unknown Type\n");
   	//its_ip(header->len,packet,here,sizeof(struct ether_header));
 }
 if(filename)		//don't close the stdout !!
  fclose(here);
}

void its_ip(int packet_len,const u_char *packet,FILE *here,int hdr_covered)
{
 fprintf(here,"\nPrinting the IP header information:\n");
 struct ip *ip_hdr; 
/*****************************************************************************
  Structure of the IP Header 
 
struct ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;               * header length *
    unsigned int ip_v:4;                * version *
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;                * version *
    unsigned int ip_hl:4;               * header length *
#endif
    u_int8_t ip_tos;                    * type of service *
    u_short ip_len;                     * total length *
    u_short ip_id;                      * identification *
    u_short ip_off;                     * fragment offset field *
#define IP_RF 0x8000                    * reserved fragment flag *
#define IP_DF 0x4000                    * dont fragment flag *
#define IP_MF 0x2000                    * more fragments flag *
#define IP_OFFMASK 0x1fff               * mask for fragmenting bits *
    u_int8_t ip_ttl;                    * time to live *
    u_int8_t ip_p;                      * protocol *
    u_short ip_sum;                     * checksum *
    struct in_addr ip_src, ip_dst;      * source and dest address *
  };
*******************************************************************************/
 ip_hdr = (struct ip *)(packet + hdr_covered);
 hdr_covered += sizeof(struct ip); 
 fprintf(here,"Source IP Address: %s\n",inet_ntoa(ip_hdr->ip_src));
 fprintf(here,"Destination IP Address: %s\n",inet_ntoa(ip_hdr->ip_dst));
 fprintf(here,"Protocol:");
 switch(ip_hdr->ip_p)
 {
  case IPPROTO_IP:
	fprintf(here,"Dummy TCP\n");
	break;
  case IPPROTO_ICMP:
	fprintf(here,"ICMP: Internet Control Message Protocol\n");
	break;
  case IPPROTO_IGMP:
	fprintf(here,"IGMP: Internet Group Management Protocol\n");
	break;
  case IPPROTO_IPIP:
	fprintf(here,"IPIP: IPIP Tunnels\n");
	break;
  case IPPROTO_TCP:
	fprintf(here,"TCP: Transmission Control Protocol\n");
	its_tcp(packet_len,packet,here,hdr_covered);
	break;
  case IPPROTO_EGP:
	fprintf(here,"EGP: Exterior Gateway Protocol\n");
	break;
  case IPPROTO_PUP:
	fprintf(here,"PUP\n");
	break;
  case IPPROTO_UDP:
	fprintf(here,"UDP: User Datagram Protocol\n");
	its_udp(packet_len,packet,here,hdr_covered);
	break;
  case IPPROTO_IDP:
	fprintf(here,"IDP: XNS IDP Protocol\n");
	break;
  case IPPROTO_TP:
	fprintf(here,"TP: SO Transport Protocol\n");
	break;
  case IPPROTO_IPV6:
	fprintf(here,"IPv6");
	break;
  case IPPROTO_RSVP:
	fprintf(here,"RSVP: Reservation Protocol\n");
	break;
  case IPPROTO_GRE:
	fprintf(here,"GRE: General Routing Encapsulation\n");
	break;
  case IPPROTO_ESP:
	fprintf(here,"ESP: Encapsulation Security Payload\n");
	break;
  case IPPROTO_AH:
	fprintf(here,"AH: Authentication Header\n");
	break;
  case IPPROTO_MTP:
	fprintf(here,"MTP: Multicast Transport Protocol\n");
	break;
  case IPPROTO_ENCAP:
	fprintf(here,"ENCAP: Encapsulation Header\n");
	break;
  case IPPROTO_PIM:
	fprintf(here,"PIM: Protocol Independent Multicasting\n");
	break;
  case IPPROTO_COMP:
	fprintf(here,"COMP: Compression Header Protocol\n");
	break;
  case IPPROTO_SCTP:
	fprintf(here,"SCTP: Stream Control Transmission Protocol\n");
	break;
  case IPPROTO_RAW:	
	fprintf(here,"RAW: RAW IP Packet\n");
	break;
  default:
 	fprintf(here,"Unknown\n");
 }
}

void its_tcp(int packet_len,const u_char *packet,FILE *here,int hdr_covered)
{
 fprintf(here,"\nPrinting the TCP header information:\n");
/************************************************************
 	TCP HEADER

# ifdef __FAVOR_BSD
typedef u_int32_t tcp_seq;

 * TCP header.
 * Per RFC 793, September, 1981.
 *
struct tcphdr
  {
    u_int16_t th_sport;         * source port *
    u_int16_t th_dport;         * destination port *
    tcp_seq th_seq;             * sequence number *
    tcp_seq th_ack;             * acknowledgement number *
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;           * (unused) *
    u_int8_t th_off:4;          * data offset *
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;          * data offset *
    u_int8_t th_x2:4;           * (unused) *
#  endif
    u_int8_t th_flags;
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH       0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20
    u_int16_t th_win;           * window *
    u_int16_t th_sum;           * checksum *
    u_int16_t th_urp;           * urgent pointer *
};

#else	* !__FAVOR_BSD *
struct tcphdr
  {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};
# endif * __FAVOR_BSD *

*************************************************************/
 struct tcphdr *tcp_hdr;
 char ser_name[SID_SNIFF_SER_MAX_LEN];
 tcp_hdr = (struct tcphdr *)(packet + hdr_covered);
 hdr_covered += sizeof(struct tcphdr);
 fprintf(here,"Source Port: %u: %s\n",tcp_hdr->source,porttoservice(tcp_hdr->source,ser_name));
 fprintf(here,"Destination Port: %u: %s\n",tcp_hdr->dest,porttoservice(tcp_hdr->dest,ser_name));
 get_data(packet_len,packet,here,hdr_covered);
}

void its_udp(int packet_len,const u_char *packet, FILE *here, int hdr_covered)
{
 fprintf(here,"\nPrinting the UDP header information:\n");
/***********************************************************
	UDP Header:

 * UDP header as specified by RFC 768, August 1980. *
#ifdef __FAVOR_BSD

struct udphdr
{
  u_int16_t uh_sport;           * source port *
  u_int16_t uh_dport;           * destination port *
  u_int16_t uh_ulen;            * udp length *
  u_int16_t uh_sum;             * udp checksum *
};

#else

struct udphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
};
#endif

#define SOL_UDP            17      * sockopt level for UDP *

#endif * netinet/udp.h *
***************************************************************/
 struct udphdr *udp_hdr;
 char ser_name[SID_SNIFF_SER_MAX_LEN];
 udp_hdr = (struct udphdr*)(packet + hdr_covered);
 hdr_covered += sizeof(struct udphdr);
 fprintf(here,"Source Port: %u: %s\n",udp_hdr->source,porttoservice(udp_hdr->source,ser_name));
 fprintf(here,"Destination Port: %u: %s\n",udp_hdr->dest,porttoservice(udp_hdr->dest,ser_name));
 get_data(packet_len,packet,here,hdr_covered);
}

void its_arp(int packet_len,const u_char *packet, FILE *here, int hdr_covered)
{
 fprintf(here,"\nPrinting the ARP header information:\n");
/*****************************************************************
	ARP Header:

* Some internals from deep down in the kernel.  *
#define MAX_ADDR_LEN    7


* This structure defines an ethernet arp header.  *

* ARP protocol opcodes. *
#define ARPOP_REQUEST   1               * ARP request.  *
#define ARPOP_REPLY     2               * ARP reply.  *
#define ARPOP_RREQUEST  3               * RARP request.  *
#define ARPOP_RREPLY    4               * RARP reply.  *
#define ARPOP_InREQUEST 8               * InARP request.  *
#define ARPOP_InREPLY   9               * InARP reply.  *
#define ARPOP_NAK       10              * (ATM)ARP NAK.  *

* See RFC 826 for protocol description.  ARP packets are variable
   in size; the arphdr structure defines the fixed-length portion.
   Protocol type values are the same as those for 10 Mbs Ethernet.
   It is followed by the variable-sized fields ar_sha, arp_spa,
   arp_tha and arp_tpa in that order, according to the lengths
   specified.  Field names used correspond to RFC 826.  *

struct arphdr
  {
    unsigned short int ar_hrd;          * Format of hardware address.  *
    unsigned short int ar_pro;          * Format of protocol address.  *
    unsigned char ar_hln;               * Length of hardware address.  *
    unsigned char ar_pln;               * Length of protocol address.  *
    unsigned short int ar_op;           * ARP opcode (command).  *
#if 0
    * Ethernet looks like this : This bit is variable sized
       however...  *
    unsigned char __ar_sha[ETH_ALEN];   * Sender hardware address.  *
    unsigned char __ar_sip[4];          * Sender IP address.  *
    unsigned char __ar_tha[ETH_ALEN];   * Target hardware address.  *
    unsigned char __ar_tip[4];          * Target IP address.  *
#endif
  };
******************************************************************************/
 struct arphdr *arp_hdr;
 arp_hdr = (struct arphdr *)(packet + hdr_covered);
 hdr_covered += sizeof(struct arphdr);
 fprintf(here,"ARP opcode: ");
 switch(arp_hdr->ar_op)
 {
  case ARPOP_REQUEST:
	fprintf(here,"ARP Request\n"); 
	break;
  case ARPOP_REPLY:
	fprintf(here,"ARP Reply\n");
	break; 
  case ARPOP_RREQUEST:
	fprintf(here,"RARP Request\n");
	break; 
  case ARPOP_RREPLY:
	fprintf(here,"RARP Reply\n");
	break; 
  case ARPOP_InREQUEST:
	fprintf(here,"InARP Request\n");
	break; 
  case ARPOP_InREPLY:
	fprintf(here,"InARP Reply\n");
	break; 
  case ARPOP_NAK:
	fprintf(here,"ATM ARP NAK\n");
	break;
  default:
	fprintf(here,"Undefined\n");  
 }
 get_data(packet_len,packet,here,hdr_covered);
}

/************************************************************
	Print the Payload
************************************************************/
void get_data(int packet_len,const u_char *packet,FILE *here,int hdr_covered)
{
#undef SID_SNIFF_ETH_TRAIL
#define SID_SNIFF_ETH_TRAIL 4
 int data_len = packet_len - hdr_covered - SID_SNIFF_ETH_TRAIL;
 fprintf(here,"\nPrinting the data remaining in the packet:\n");
 for(data_len = packet_len - hdr_covered;data_len > 0;data_len--)
  fprintf(here,"%c ",*packet++);
}


char *porttoservice(int port,char *ser)
{
/********************************************************************************
	* Standard well-known ports.  *
enum
  {
    IPPORT_ECHO = 7,            * Echo service.  *
    IPPORT_DISCARD = 9,         * Discard transmissions service.  *
    IPPORT_SYSTAT = 11,         * System status service.  *
    IPPORT_DAYTIME = 13,        * Time of day service.  *
    IPPORT_NETSTAT = 15,        * Network status service.  *
    IPPORT_FTP = 21,            * File Transfer Protocol.  *
    IPPORT_TELNET = 23,         * Telnet protocol.  *
    IPPORT_SMTP = 25,           * Simple Mail Transfer Protocol.  *
    IPPORT_TIMESERVER = 37,     * Timeserver service.  *
    IPPORT_NAMESERVER = 42,     * Domain Name Service.  *
    IPPORT_WHOIS = 43,          * Internet Whois service.  *
    IPPORT_MTP = 57,

    IPPORT_TFTP = 69,           * Trivial File Transfer Protocol.  *
    IPPORT_RJE = 77,
    IPPORT_FINGER = 79,         * Finger service.  *
    IPPORT_TTYLINK = 87,
    IPPORT_SUPDUP = 95,         * SUPDUP protocol.  *


    IPPORT_EXECSERVER = 512,    * execd service.  *
    IPPORT_LOGINSERVER = 513,   * rlogind service.  *
    IPPORT_CMDSERVER = 514,
    IPPORT_EFSSERVER = 520,

    * UDP ports.  *
    IPPORT_BIFFUDP = 512,
    IPPORT_WHOSERVER = 513,
    IPPORT_ROUTESERVER = 520,

    * Ports less than this value are reserved for privileged processes.  *
    IPPORT_RESERVED = 1024,

    * Ports greater this value are reserved for (non-privileged) servers.  *
    IPPORT_USERRESERVED = 5000
  };
 *******************************************************************************/
if(port < IPPORT_RESERVED)
 switch(port)
 {
  case 7:	strcpy(ser,"Echo service.");			break;
  case 9:	strcpy(ser,"Discard transmissions service."); 	break;
  case 11:	strcpy(ser,"System status service.");		break;
  case 13:	strcpy(ser,"Time of day service.");		break;
  case 15:	strcpy(ser,"Network status service." );		break;
  case 21:	strcpy(ser,"File Transfer Protocol.");		break;
  case 23:	strcpy(ser,"Telnet protocol.");			break;
  case 25:	strcpy(ser,"Simple Mail Transfer Protocol.");	break;
  case 37:	strcpy(ser,"Timeserver service.");		break;
  case 42:	strcpy(ser,"Domain Name Service.");		break;
  case 43:	strcpy(ser,"Internet Whois service.");		break;
  case 69:	strcpy(ser,"Trivial File Transfer Protocol.");	break;
  case 79:	strcpy(ser,"Finger service.");			break;
//  case 80:strcpy(ser,"HTTP service.");break;
  case 95:	strcpy(ser,"SUPDUP protocol.");			break;
  case 512:	strcpy(ser,"execd service.");			break;
  case 513:	strcpy(ser,"rlogind service.");			break;
  default:	strcpy(ser,"unknown system service");
 }
else
 strcpy(ser,"user-defined service");
return ser;
}
