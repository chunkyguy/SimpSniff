/***********************************************************
	sidsniff : The Packet Sniffer
***********************************************************/

#include"sniff.h"

#define TIME 5
#define MAN_SIZE 15		//0.0.0.0 to 255.255.255.255


int main()
{
 int i;
 int mode;			//manual (1) or automatic (0)
 char *dev;			//device
 char netipdot[MAN_SIZE];	//network address in dot-notation
 char maskdot[MAN_SIZE];	//mask in dot-notation
 char errbuf[PCAP_ERRBUF_SIZE];	//for error handling 
 bpf_u_int32 netip;		//network addr
 bpf_u_int32 mask;		//subnet mask
 int ret;			//return code of pcap_lookupnet()
 struct in_addr netaddr,maskaddr;	//the network address @ "netinet/in.h"
 pcap_t *handle;		//session handle
 int timeout;			//read timeout for sniffing session
 int packet_count;		//total pcakets to be captured
 char log_choice;		//wanna create log file ??
 char file[25]={0};		//space for filename
 char *file_ptr;		//for sending filename to callback
 int packets_read;		//total no. of packets read
 /************for manual override********************************/
 char manual[MAN_SIZE];		//for manual overriding purpose 
 int bufsize;			//buffer size 
 int sniffmode;			//promiscuous ?? ;)
 pcap_if_t *devlist;		//to hold the list of all devices
 int devno;			//device number
 FILE *f;			//file pointer for adding initial information to the log file

 /***********************************************************
  	Setting up the interface
 *************************************************************/

 printf("Press ENTER key to enter the manual mode ...\n");
 mode = timer(TIME);

 if(mode)
 {
  printf("Interfaces found :\n");
  pcap_findalldevs(&devlist,errbuf);
  printf("S.No\tDevice/Interface\tNetwork Address\t\tSubnet Mask\n");
  while(devlist!=NULL)
  {
   printf("%d",++devno);
   printf("\t%s",devlist->name);
   pcap_lookupnet(devlist->name, &netip, &mask ,errbuf);
   netaddr.s_addr = netip;
   printf("\t\t\t%s",(char *)inet_ntoa(netaddr));
   maskaddr.s_addr = mask;
   printf(" \t\t%s",(char *)inet_ntoa(maskaddr));
   devlist = devlist->next;
   printf("\n");
  }
  printf("\nEnter the device or interface you want to sniff on ..\t:");
  scanf(" %s",manual);
  dev = manual;
 }
 
 else
 {
	/***********************************************************
		Prototype of pcap_lookupdev:

	 char *pcap_lookupdev(char *errbuf);
	************************************************************/
  dev=pcap_lookupdev(errbuf);
  if(dev==NULL)
   errors(errbuf);
  printf("Device: %s\n",dev);
 }
	/***********************************************************
		Prototype of pcap_lookupnet:

	 int pcap_lookupnet(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf);
	************************************************************/
  ret = pcap_lookupnet(dev, &netip, &mask, errbuf);
  if(ret==-1)
   errors(errbuf);

  netaddr.s_addr = netip;	
	/***********************************************************
 		Prototype of inet_ntoa:

	 char *inet_ntoa(struct in_addr in);
	*************************************************************/
  strcpy(netipdot,(char *)inet_ntoa(netaddr));
  if(inet_ntoa(netaddr)==0)
   errors("sniffer: error in obtaining IP Address\n");
  printf("Network Address: %s\n",netipdot);

  maskaddr.s_addr = mask;
  strcpy(maskdot,(char *)inet_ntoa(maskaddr));
  if(inet_ntoa(maskaddr)==0)
   errors("sniffer: error in obtaining Subnet Mask\n");
  printf("Subnet Mask: %s\n",maskdot);
  

 /***********************************************************
 	Starting Sniffing Session
 *************************************************************/
 if(mode)
 {
  printf("\nEnter the size of the buffer to hold the pcakets\n"
	"(recommended value is %d) \t:",BUFSIZ);
  scanf(" %d",&bufsize);
  printf("\nEnter the mode of sniffing \n1: Promiscuous\n0: Non-Promiscuous\t:");
  scanf(" %d",&sniffmode);
  printf("\nEnter the read timeout in milliseconds\n"
 	" 0: Until an error occurs\n"
 	"-1: Indefinitely\n"
 	"(This value may get overwritten later on !!)\t:");
  scanf(" %d",&timeout);
 }
 else
 {
  bufsize = BUFSIZ;
  sniffmode = 1;
  timeout = 0;
 }
	/***********************************************************
		Prototype of pcap_open_live:

 	pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf);
	*************************************************************/
 printf("\nOpening sniffing session ....\n");
 handle = pcap_open_live(dev,bufsize,sniffmode,timeout,errbuf);
 if(handle == NULL)
  errors(errbuf);
 printf("Sniffing session created for device %s.\n",dev);

/************************************************************
	Capturing Packets                                    
*************************************************************/
 printf("\nEnter the total no of packets to be captured"
	" (-ve value means until some error occurs)\t:");
 scanf(" %d",&packet_count);

 printf("\nDo you want to create a log file of this session (y/n)\t:");
 scanf(" %c",&log_choice);
 if(log_choice == 'y')
 {
  createfln(file);
  printf("%s Created ...\n",file);
  file_ptr = file;	//send filename
  /************ Adding attributes to the log file ***************/
  f = fopen(file,"w");
  if(f==NULL)
   errors("Unable to open log file");
  printf("log file opened ...\n");
  printf("Adding initial information to the log file ...\n");
  fprintf(f,"Device: %s\n",dev);
  fprintf(f,"Network Address: %s\n",netipdot);
  fprintf(f,"Subnet Mask: %s\n",maskdot);
  fprintf(f,"Buffer Size: %d\n",bufsize);
  fprintf(f,"Sniffing mode promiscuous ?: %c\n",(sniffmode)?'Y':'N');
  fprintf(f,"Timeout :%d\n",timeout);
  fprintf(f,"Packets Requested: %d\n",packet_count);
  fclose(f);
 }
 else
  file_ptr = 0;		//send no filename 
	/***********************************************************
 		Prototype of pcap_loop:

 	int pcap_loop(pcap_t *handle, int count, pcap_handler callback, u_char *user);
	************************************************************/
 packets_read = pcap_loop(handle,packet_count,packet_found,(u_char *)file_ptr);


/***********************************************************
	Closing Sniffing Session
***********************************************************/
 printf("\nClosing sniffing session ...\n");
 if(mode)
 {
  printf("Freeing all devices ...\n"); 
  pcap_freealldevs(devlist); //free al devices allocated by pcap_findalldevs()
 }
// printf("Total pcakets captured: %d\n",packets_read);
 if(packets_read == -1)
 {
  pcap_perror(handle,errbuf);
  errors(errbuf);
 }
 if(packets_read == -2)
  errors("loop terminated due to call of pcap_breakloop() !");
 pcap_close(handle);
}

/************************************************************
	Create Filename
*************************************************************/
void createfln(char *fln)
{
 char timestamp[25];		//timestamp on the file
 char *p;
 time_t fileid;			//include<time.h> id used for log file 
 time(&fileid);
 
 sprintf(timestamp,"%s",ctime((time_t *)&fileid));
 for(p=timestamp;*p!='\0';p++)
  if(isspace(*p)|| *p==':')
   *p = '_';
 sprintf(fln,"%s%s%s","Sniff_",timestamp,".log");
}
/************************************************************
	 For error handling 
*************************************************************/

void errors(char *err)
{
 printf("\n%s\n%s\n%s\n","ERROR: ",err,"Thanks for using SidSniff");
 exit(1);
}

