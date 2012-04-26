#include "Sender_Task.h"
#include "Queue_Manager.h"
#include "Reciever_Task.h"
#include "DNS_Resolver.h"

Sender_Task::Sender_Task() {
    if ((m_senderSocketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(stderr, "Error opening sending socket\n");
    }
}
Sender_Task::~Sender_Task(){}

void *Sender_Task::sender_run(void *args) {
    struct packet_info *current_info;
    struct sender_args *sender_args = (struct sender_args *)args;
    Queue_Manager *queue_manager = (Queue_Manager *)sender_args->queue_manager;
    DNS_Resolver *dns_resolver = (DNS_Resolver *)sender_args->dns_resolver;

    while(true) {
        current_info = queue_manager->deque();
        fprintf(stderr, "Deque'd packet_info: %p, len: %d\n", current_info, current_info->size);
        dns_resolver->resolve(current_info);
    }

    return (void *)0;
}

void Sender_Task::query_root(struct packet_info *info, struct sockaddr_in *client) {

    struct sockaddr_in saddr_root;
    socklen_t saddr_root_len = sizeof(saddr_root);

    memset((u_char *)&saddr_root, 0, sizeof(saddr_root));
    saddr_root.sin_family = AF_INET;
    saddr_root.sin_port = htons(PORT_DNS);

    if (inet_aton(DNS_Resolver::m_rootServerStrings[0].c_str(), &saddr_root.sin_addr) == 0) { 
        fprintf(stderr, "Error could not convert root server ip string\n");
    } 

    uint16_t *flags = &(((struct dns_header *)info->packet)->codesFlags);
    *flags = (int)*flags & (1 << 8);  

    if (sendto(m_senderSocketfd, info->packet, info->size, 0, (struct sockaddr *)&saddr_root, saddr_root_len) == -1) {
        perror("Error could not send packet to root server\n");
    }    
}

