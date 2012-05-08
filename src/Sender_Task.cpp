#include "Sender_Task.h"
#include "Queue_Manager.h"
#include "Reciever_Task.h"
#include "DNS_Resolver.h"

#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>

Sender_Task::Sender_Task(){}
Sender_Task::~Sender_Task(){}

void *Sender_Task::sender_run(void *args) {
    struct packet_info *current_info = NULL;
    struct sender_args *sender_args = (struct sender_args *)args;
    Queue_Manager *queue_manager = (Queue_Manager *)sender_args->queue_manager;
    DNS_Resolver *dns_resolver = (DNS_Resolver *)sender_args->dns_resolver;

    dns_resolver->create_resolver_binding();
    
    while(true) {
        if (queue_manager->deque(&current_info) == 1) {        
            
            if (DEBUG)
                fprintf(stderr, "Deque'd packet_info: %p\n", current_info);

            dns_resolver->handle_query(current_info);

            delete current_info;
        }
    }

    return (void *)0;
}

int Sender_Task::return_response(packet_info *info, sockaddr_in *addr, int sock) {

    struct sockaddr_in saddr;
    socklen_t saddr_len = sizeof(saddr);

    memset((u_char *)&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = ((sockaddr_in6 *)addr)->sin6_port;

    string address = "127.0.0.1"; 

    if (inet_pton(AF_INET, address.c_str(), &(saddr.sin_addr)) == 0) { 
        perror("Error could not convert\n");
    } 
    
    if (sendto(sock, info->packet, info->size, 0, (struct sockaddr *)&saddr, saddr_len) == -1) {
        perror("Error could not return\n");
    }
    return 1;
}

int Sender_Task::query_address(packet_info *info, vector<uint32_t> *addresses, int sock) {
    struct sockaddr_in saddr_root;
    socklen_t saddr_root_len = sizeof(saddr_root);

    memset((u_char *)&saddr_root, 0, sizeof(saddr_root));
    saddr_root.sin_family = AF_INET;
    saddr_root.sin_port = htons(PORT_DNS);
   
     uint16_t *flags_bits  = &(((struct dns_header *)info->packet)->codesFlags);
    *flags_bits = ntohs(*flags_bits) & ~(1 << 7); 

    vector<uint32_t>::iterator it;
    for (it = addresses->begin(); it != addresses->end(); ++it) {
        saddr_root.sin_addr.s_addr = (int)(*it);

        if (sendto(sock, info->packet, info->size, 0, (struct sockaddr *)&saddr_root, saddr_root_len) == -1) {
            perror("Error could not send packet to root server\n");
        }

        if(Sender_Task::select_call(DEFAULT_TIMEOUT, 0, sock)) {
            return 1;
        }
    }
    return 0;
}

int Sender_Task::query_root(struct packet_info *info, int sock) {
    struct sockaddr_in saddr_root;
    socklen_t saddr_root_len = sizeof(saddr_root);

    memset((u_char *)&saddr_root, 0, sizeof(saddr_root));
    saddr_root.sin_family = AF_INET;
    saddr_root.sin_port = htons(PORT_DNS);
   
     uint16_t *flags_bits  = &(((struct dns_header *)info->packet)->codesFlags);
    *flags_bits = ntohs(*flags_bits) & ~(1 << 7); 
 
    for (int i=ROOT_SERVERS_LEN-1; i>=0; i--) {
        char *address = (char *)m_rootServerStrings[i].c_str();

        if (inet_aton(address, &saddr_root.sin_addr) == 0) { 
            fprintf(stderr, "Error could not convert root server ip string\n");
        } 

        if (sendto(sock, info->packet, info->size, 0, (struct sockaddr *)&saddr_root, saddr_root_len) == -1) {
            perror("Error could not send packet to root server\n");
        }

        if(Sender_Task::select_call(DEFAULT_TIMEOUT, 0, sock)) {
            return 1;
        }    
    }
    return 0;   
}

int Sender_Task::select_call(int seconds, int useconds, int sock) {
   //setup vars
   static struct timeval timeout;
   fd_set fdvar;

   //setup timeout
   timeout.tv_sec = seconds;
   timeout.tv_usec = 0;
   FD_ZERO(&fdvar);
   FD_SET(sock, &fdvar);

   return (select(sock+1, (fd_set *)&fdvar, (fd_set *)0, (fd_set *)0, &timeout));
}

const SMA::string Sender_Task::m_rootServerStrings[] =
                       {"198.41.0.4", "192.228.79.201", "192.33.4.12",
                        "128.8.10.90", "192.203.230.10", "192.5.5.241",
                        "192.112.36.4", "128.63.2.53", "192.36.148.17",
                        "192.58.128.30", "193.0.14.129", "199.7.83.42",
                        "202.12.27.33"};
