#include<pcap.h>
#include<stdio.h>
#include<netinet/if_ether.h>
#include<netinet/in.h>		//for struct in_addr to convert ip to dot-notation & various macros def.
#include<sys/poll.h>		//for poll() syscall in timer()  
#include<string.h>
#include<netinet/ip.h>		//ip header
#include<netinet/tcp.h>		//tcp header
#include<netinet/udp.h>		//udp header
#include<net/if_arp.h>		//arp header
#include<time.h>		//timestamp to log file

int timer(int time);		 //ret: 1 timer interrupted; 0 timer completes
void errors(char *);		 //error handling
void packet_found(u_char *,const struct pcap_pkthdr *,const u_char *);		//The Callback 
/*
*	all these functions have following arguments:
*	const u_char *packet: 	The packet sniffed
*	FILE *here:		The data stream where the output is to be send
*	int hdr_covered:	The size of headers covered so far starting from ethernet header
*/
void its_ip(int ,const u_char *,FILE *,int);		//if its ip header
void its_tcp(int ,const u_char *,FILE *,int);	//tcp header
void its_udp(int ,const u_char *,FILE *,int);	//udp header
void its_arp(int ,const u_char *,FILE *,int);	//arp header
void get_data(int ,const u_char *,FILE *,int);
char *porttoservice(int port_no,char *service);	//ret: ptr to service of len SID_SNIFF_SER_MAX_LEN @ 'callback.h'
void createfln(char *);		//creating log filename
