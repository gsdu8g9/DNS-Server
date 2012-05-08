#include "DNS_Resolver.h"
#include "Reciever_Task.h"
#include <sys/time.h>

using namespace SMA;

DNS_Resolver::DNS_Resolver()
    : m_senderTask(new Sender_Task()), m_dnsParser(new DNS_Parser())
{}
DNS_Resolver::~DNS_Resolver() {
    delete m_senderTask;
    delete m_dnsParser;
}

void DNS_Resolver::handle_query(packet_info *pkt_info) {
    dns_header *dns = (struct dns_header *)pkt_info->packet; 
    uint16_t flags_order = ntohs(dns->codesFlags);

    m_query = pkt_info;

    if (DEBUG) {
        fprintf(stderr, "Original Query:\n");
        Reciever_Task::print_buf(pkt_info->packet, pkt_info->size);   
    }
    if (!(flags_order & (1<<DNS_Resolver::RD))) {
        if (DEBUG)
            fprintf(stderr, "Got iterative query!\n");
        //handle iterative query     
    } else {
        if(m_senderTask->query_root(pkt_info, m_currentSocket)) {   
            packet_info *new_info = new packet_info();
            socklen_t client_len = sizeof(sockaddr_in6);
            if ((new_info->size = recvfrom(m_currentSocket, new_info->packet,  MAX_DNS_LEN, 0, (struct sockaddr *)new_info->client, &client_len)) == -1) {
                return;
            }

            DNS_Resolver::resolve(new_info);
            delete new_info;
        } else {
            //handle non-responsive name server 
        }
    }
}

int DNS_Resolver::resolve(packet_info *pkt_info) {
    dns_info *dns_inf = m_dnsParser->parse_response(pkt_info);
    
    if (DEBUG)
        Reciever_Task::print_buf(pkt_info->packet, pkt_info->size);   

    if (dns_inf->answers->size() > 0) {
        m_senderTask->return_response(pkt_info, (struct sockaddr_in *)(m_query->client), m_query->sock); 
        delete dns_inf;
        return 1;
    }    

    vector<dns_record *>*returnable = DNS_Resolver::find_returnable_record(dns_inf);
    if (returnable->size() == 0) {
        
        vector<dns_record *>::iterator it;
        for (it = ((vector<dns_record *> *)dns_inf->auth_answers)->begin(); it != ((vector<dns_record *> *)dns_inf->auth_answers)->end(); ++it) {
            packet_info *pkt = DNS_Resolver::build_question((dns_record *)*it);
            if (m_senderTask->query_root(pkt, m_currentSocket) ) {   
                
                socklen_t client_len = sizeof(sockaddr_in6);
                packet_info *new_info = new packet_info();
                if ((new_info->size = recvfrom(m_currentSocket, new_info->packet,  MAX_DNS_LEN, 0, (struct sockaddr *)new_info->client, &client_len)) == -1) {
                    delete pkt;
                    delete new_info;
                    delete dns_inf;
                    return -1;
                }
                DNS_Resolver::resolve(new_info);                
                delete new_info;
                delete pkt;
                
                break;
            } else {
                delete pkt;
            }
        }
    } else {
        uint16_t type;
        vector<uint32_t> *addresses = new vector<uint32_t>();
        vector<dns_record *>::iterator it;
        for (it = returnable->begin(); it != returnable->end(); ++it) {
            type = ntohs(((dns_record *)*it)->type);
            if (type == A) {
                addresses->push_back( ((a_record *)*it)->ip_address);
            }
        }
        returnable->clear();
        delete returnable;
  
        socklen_t client_len = sizeof(sockaddr_in6);
        if (m_senderTask->query_address(m_query, addresses, m_currentSocket)) {
            packet_info *new_info = new packet_info(); 
            if ((new_info->size = recvfrom(m_currentSocket, new_info->packet,  MAX_DNS_LEN, 0, (struct sockaddr *)new_info->client, &client_len)) == -1) {
                delete new_info;
                return -1;
            }
            DNS_Resolver::resolve(new_info);
            delete new_info;
        }
        addresses->clear(); 
        delete addresses;
    }
    
    delete dns_inf;
    return 1;
}

vector<dns_record *> *DNS_Resolver::find_returnable_record(dns_info *info) {
    vector<dns_record *> *answers = info->answers;
    vector<dns_record *> *auth_answers = info->auth_answers;
    vector<dns_record *> *add_answers = info->add_answers;

    vector<dns_record *> *returnable_records = new vector<dns_record *>(); 
 
    vector<dns_record *>::iterator it;
    for (it = answers->begin(); it != answers->end(); ++it) {
        if (DNS_Resolver::is_returnable_record(*it)) 
            returnable_records->push_back(*it);
    }

    for (it = auth_answers->begin(); it != auth_answers->end(); ++it) {
        if (DNS_Resolver::is_returnable_record(*it)) 
            returnable_records->push_back(*it);
    }

    for (it = add_answers->begin(); it != add_answers->end(); ++it) {
        if (DNS_Resolver::is_returnable_record(*it)) 
            returnable_records->push_back(*it);
    }
    
    return returnable_records;
}

bool DNS_Resolver::is_returnable_record(dns_record *record) {
    bool return_type = false;
    uint16_t type = ntohs(record->type);
    
    switch (type) {
        case A:
            return_type = true;
            break;
        case MX:
            return_type = true;
            break;
        case SOA:
            return_type = true;
            break;
        case PTR:
            return_type = true;
            break;
        case CNAME:
            return_type = true;
            break;
        default:
            return_type = false;
            break;   
    }
    return return_type; 
}

packet_info *DNS_Resolver::build_question(dns_record *record) {
    int add_space = 0;
    int query_length = DNS_Resolver::length_query_name(((ns_record *)record)->name_server)+1;
    add_space += sizeof(uint32_t);
    add_space += query_length;
    
    u_char *query = DNS_Resolver::encode_query_name( ((ns_record *)record)->name_server, query_length);
    
    packet_info *pkt_info = new packet_info(); 
    dns_header *dns = (dns_header *)pkt_info->packet;

    dns->transID = htons(0x045);
    dns->totalQuestions = htons(1);
    
    memcpy( (u_char *)((u_char *)dns + sizeof(dns_header)), query, query_length);
    memcpy( (u_char *)((u_char *)dns + sizeof(dns_header) + query_length), &record->classt, sizeof(uint16_t));
    memcpy( (u_char *)((u_char *)dns + sizeof(dns_header) + query_length + sizeof(uint16_t)), &record->classt, sizeof(uint16_t));

    pkt_info->size = sizeof(dns_header) + add_space;
    
    free(query);
    return pkt_info; 
}

int DNS_Resolver::length_query_name(vector<string> *labels) {
    int size = 0;
    vector<string>::iterator it;
    for (it = labels->begin(); it != labels->end(); ++it) {
        char *cstr  = (char *)(((string)*it).c_str());
        size += strlen(cstr);
    }
    return size + labels->size();
}

u_char *DNS_Resolver::encode_query_name(vector<string> *labels, int size) {
    u_char *query = (u_char *)calloc(size, 1);
    u_char *q_ptr = query;

    vector<string>::iterator it;
    for (it = labels->begin(); it != labels->end(); ++it) {
        uint8_t chunk_size = strlen((char *)(((string)*it).c_str()));
        memcpy(q_ptr, &chunk_size, sizeof(uint8_t));
        q_ptr += sizeof(uint8_t);
        
        memcpy(q_ptr, (char *)(((string)*it).c_str()), chunk_size);
        q_ptr += chunk_size;        
    }
    return query;
} 

void build_empty_cache_response() {}

u_char *build_cache_response(struct dns_response *response) {
    return (u_char *)-1;
}

int DNS_Resolver::create_resolver_binding() {
    int socketfd;
    struct sockaddr_in6 saddr;

    if ((socketfd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(stderr, "Error creating socket!\n");
        return -1;
    }

    memset((char *) &saddr, 0, sizeof(saddr));
    saddr.sin6_family = AF_INET;
    saddr.sin6_port = htons(0);
    saddr.sin6_addr = in6addr_any;

    if (bind(socketfd, (struct sockaddr *)&saddr, sizeof(saddr))==-1) {
        fprintf(stderr, "bind");
        return -1;
    }

    //fprintf(stderr, "Second socket bound to port: %d\n", ntohs(saddr.sin_port));
    m_currentSocket = socketfd;

    return 0;
}
