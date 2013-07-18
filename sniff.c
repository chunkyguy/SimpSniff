/***************************************************************************
                          main.c  -  description
                             -------------------
    begin                : Thu Jun 15 08:00 IST 2006
    email                : amitsaha.in@gmail.com
 ***************************************************************************/
	/*	Copyright owned by Tim Carstens */
/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
                                               
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        //u_short ether_type;                     /* IP? ARP? RARP? etc */
        //u_short p_add_space;
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv)
{
  int dev; /* name of the device to use */
  char *net; /* dot notation of the network address */
  char *mask;/* dot notation of the network mask    */
  int num_dev;   /* return code */
  struct pcap_pkthdr header;
  const u_char *packet;           /* The actual packet */
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp; /* ip          */
  bpf_u_int32 maskp;/* subnet mask */
  struct in_addr addr;
  pcap_if_t *alldevsp,*temp_alldevsp;
  char sniff_dev[10];
  int num_packets = 10;

  /* ask pcap to find a valid device for use to sniff on */
    pcap_t *handle;
   num_dev=pcap_findalldevs(&alldevsp,errbuf);
   temp_alldevsp=alldevsp;
   if(num_dev==0)   /* device lookup success */
            {
            printf("\n\tNetwork Devices found\n\t--------------------\n");
            while(temp_alldevsp!=NULL){
              printf("Device Name ::%s\n",temp_alldevsp->name);
              temp_alldevsp=temp_alldevsp->next;
              
              }
            }

temp_alldevsp=alldevsp;
   printf("\n\tNetwork Device Information\n\t--------------------\n");
            while(temp_alldevsp!=NULL){
              printf("\n\nDevice Name ::%s",temp_alldevsp->name);
              if(temp_alldevsp->description!=NULL)
                    printf("\nDevice Description ::%s",temp_alldevsp->description);
              else
                    printf("\nNo description available for this device");
                    
              if(temp_alldevsp->flags & PCAP_IF_LOOPBACK==1)
                    printf("\nDevice is a Loopback device\n\n");
              temp_alldevsp=temp_alldevsp->next;
              }
  
              
   printf("\n Enter the device name to sniff on,press enter to sniff on all devices  ");
   scanf("%s",&sniff_dev);
   handle = pcap_open_live(sniff_dev, BUFSIZ, 1, 1000, errbuf);
     if (handle == NULL) {
             fprintf(stderr, "Couldn't open device %s:\n",errbuf);
                   }
                 else
                 {
                  /* 
                 printf("\n\n\n%s opened for capture",sniff_dev);
                while(1){
                packet = pcap_next(handle, &header);
                /* Print its length */
                //printf("Jacked a packet with length of [%d] \n", header.len);
                /* And close the session */
                   /* now we can set our callback function */
                   pcap_loop(handle, num_packets, got_packet, NULL);

                }
                

   pcap_close(handle);
            
  

                                                                                                                          
  return 0;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

 /* get ethernet header informatiom*/
 
 fprintf(stdout,"\nSource MAC address: %s"
            ,ether_ntoa(ethernet->ether_shost));
 fprintf(stdout," \nDestination MAC address: %s \n"
            ,ether_ntoa(ethernet->ether_dhost));


/* fprintf(stdout," \nEther type: %u \n"
            ,(u_short)ethernet->ether_type);   // get packet type IP,RARP,etc
  fprintf(stdout," \nProtocol Address: %u \n"
            ,(u_short)ethernet->p_add_space);   // get packet type IP,RARP,etc
            */
            

	/* define compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("\nProtocol: TCP\t");
			break;
		case IPPROTO_UDP:
			printf("   \nProtocol: UDP\n\t");
			return;
		case IPPROTO_ICMP:
			printf("   \nProtocol: ICMP\n\t");
			return;
		case IPPROTO_IP:
			printf("   \nProtocol: IP");
			return;
		default:
			printf("   \nProtocol: unknown\n");
			return;
  //this part can be extended to make your sniffer analyse other higher level packets
  //check for the variuos macros in netinet/in.h
  }

	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("   Src port: %d\t", ntohs(tcp->th_sport));
	printf("   Dst port: %d\t", ntohs(tcp->th_dport));
  printf("   TCP flags: 0x%x\n",(tcp->th_flags));  

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}                                      
  

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}


