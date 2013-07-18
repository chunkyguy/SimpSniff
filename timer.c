/*****************************************
 run the timer for specified no of seconds or some interrupts occurs like pressing ENTER key
*****************************************/

#include"sniff.h"
int timer(int time)
{
 int ret;
 /********************************************
  struct pollfd {
 	int fd;		file descriptor
	short events;	requested events
	short revents;	returned events
	};
 ********************************************/
 struct pollfd *pfd= (struct pollfd *)malloc(sizeof(struct pollfd));
 pfd->fd = 0;
 pfd->events = POLLIN;
 /********************************************
 int poll(struct pollfd *fds,unsigned int nfds,int timeout_ms);
 **********************************************/
 while(time && !poll(pfd,1,1000))
 {
  printf("%d ",time--);
  fflush(stdout); 
 }
 ret = pfd->revents;
 free(pfd);
return ret;
}
