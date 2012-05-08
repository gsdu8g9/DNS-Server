#include "Reciever_Task.h"
#include "Queue_Manager.h"
#include "structures.h"
#include "net_includes.h"

Reciever_Task::Reciever_Task(){}
Reciever_Task::~Reciever_Task(){}

void *Reciever_Task::reciever_run(void *args){
    Queue_Manager *queue_manager = (Queue_Manager *)args;
    int socketfd;

    if ((socketfd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(stderr, "Error creating socket!\n");
        return (void *)-1;
    }

    struct sockaddr_in6 saddr;
    socklen_t client_len = sizeof(saddr);
    
    memset((char *) &saddr, 0, sizeof(saddr));
    
    saddr.sin6_family = PF_INET6;
    saddr.sin6_port = htons(PORT_DNS);
    saddr.sin6_addr = in6addr_any;
    if (bind(socketfd, (struct sockaddr *)&saddr, sizeof(saddr))==-1) {
        fprintf(stderr, "xbind");
        return (void *)-1;
    }
  
    packet_info *current_info = new packet_info();	
    while ((current_info->size = recvfrom(socketfd, current_info->packet, MAX_DNS_LEN, 0, (struct sockaddr *)current_info->client, &client_len)) > 0) {
        current_info->sock = socketfd;

        queue_manager->enque(current_info);    
        
        if (DEBUG)
            fprintf(stderr, "Enqueued Packet of size: %d\n", current_info->size);

        current_info = new packet_info();
    }
    delete current_info;
	close(socketfd);
    return (void *)0;
}

void Reciever_Task::print_buf(u_char *buf, int size) {
    int i;
    for (i=0; i<size; i++) 
        fprintf(stderr, "%x ", buf[i]);
}

