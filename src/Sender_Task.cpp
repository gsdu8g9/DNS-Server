#include "Sender_Task.h"
#include "Queue_Manager.h"
#include "Reciever_Task.h"
#include "DNS_Resolver.h"

Sender_Task::Sender_Task(){}
Sender_Task::~Sender_Task(){}

void *Sender_Task::sender_run(void *args) {
    struct packet_info *current_info;
    struct sender_args *sender_args = (struct sender_args *)args;
    Queue_Manager *queue_manager = (Queue_Manager *)sender_args->queue_manager;
    DNS_Resolver *dns_resolver = (DNS_Resolver *)sender_args->dns_resolver;

    dns_resolver->create_resolver_binding();

    while(true) {
        current_info = queue_manager->deque();
        fprintf(stderr, "Deque'd packet_info: %p\n", current_info);
        dns_resolver->resolve(current_info);
    }

    return (void *)0;
}

void Sender_Task::query_root(struct packet_info *info, char *address, int sock) {

    struct sockaddr_in saddr_root;
    socklen_t saddr_root_len = sizeof(saddr_root);

    memset((u_char *)&saddr_root, 0, sizeof(saddr_root));
    saddr_root.sin_family = AF_INET;
    saddr_root.sin_port = htons(PORT_DNS);

    if (inet_aton(address, &saddr_root.sin_addr) == 0) { 
        fprintf(stderr, "Error could not convert root server ip string\n");
    } 

    uint16_t *flags_bits  = &(((struct dns_header *)info->packet)->codesFlags);
    *flags_bits = ntohs(*flags_bits) & ~(1 << 7); 

    if (sendto(sock, info->packet, info->size, 0, (struct sockaddr *)&saddr_root, saddr_root_len) == -1) {
        perror("Error could not send packet to root server\n");
    }    
}

