#include "Reciever_Task.h"
#include "Queue_Manager.h"
#include "structures.h"
#include "net_includes.h"

Reciever_Task::Reciever_Task(){}
Reciever_Task::~Reciever_Task(){}

void *Reciever_Task::reciever_run(void *args){
    Queue_Manager *queue_manager = (Queue_Manager *)args;
    int socketfd;
    int packet_len;

    unsigned char *pkt_buf = (u_char *)calloc(MAX_DNS_LEN, 1);	

    struct sockaddr_in saddr, saddr_client;
    socklen_t client_len = sizeof(saddr_client);

    if ((socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
        fprintf(stderr, "Error creating socket!\n");
        return (void *)-1;
    }
    memset((char *) &saddr, 0, sizeof(saddr));
    memset((char *) &saddr_client, 0, sizeof(saddr_client));
    
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(PORT_DNS);
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(socketfd, (struct sockaddr *)&saddr, sizeof(saddr))==-1) {
        fprintf(stderr, "xbind");
        return (void *)-1;
    }
  
    while ((packet_len = recvfrom(socketfd, pkt_buf, MAX_DNS_LEN, 0, (struct sockaddr *)&saddr_client, &client_len)) > 0) {
        struct packet_info *current_info = (struct packet_info *)calloc(sizeof(struct packet_info), 1);
        current_info->packet = pkt_buf;
        current_info->size = packet_len; 
        current_info->client = &saddr_client;
        queue_manager->enque(current_info);    
        pkt_buf = (u_char *)calloc(MAX_DNS_LEN, 1);	
    }

	printf("listener done");

  free(pkt_buf);

	close(socketfd);
   return (void *)0;
}

void Reciever_Task::print_buf(u_char *buf, int size) {
    int i;
    for (i=0; i<size; i++) 
        fprintf(stderr, "%x ", buf[i]);
}

int Reciever_Task::create_listener_socket() {
    int sockfd;

    if ((sockfd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("Error creating listening socket\n");
        return -1;
    }
    return sockfd;
}