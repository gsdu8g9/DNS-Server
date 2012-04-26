#include "DNS_Resolver.h"
#include "Reciever_Task.h"
#include <iostream>
using namespace std;

DNS_Resolver::DNS_Resolver()
    : m_senderTask(new Sender_Task())
{
    int i;
    for (i=0; i<ROOT_SERVERS_LEN; i++) {
        m_rootServerBinary[i] = inet_addr(m_rootServerStrings[i].c_str());
    }    
}
DNS_Resolver::~DNS_Resolver() {
    delete m_rootServerBinary;
    delete m_senderTask;
}

void *DNS_Resolver::resolve(struct packet_info *pkt_info) {
    struct dns_header *dns = (struct dns_header *)pkt_info->packet; 
    bitset<SIZE_DNS_FLAGS> flags_bits (ntohs(dns->codesFlags));

    struct dns_info *dns_inf;      
    
    if (flags_bits.test(DNS_Resolver::QR)) {
        int i = 0;
        i++;
    } else {
        dns_inf = DNS_Resolver::parse_query(pkt_info);
    }

    m_senderTask->query_root(pkt_info, pkt_info->client);    
    fprintf(stderr, "Queried root!\n");
    return (void *)0;
}

struct dns_info *DNS_Resolver::parse_query(struct packet_info *pkt_info) {
    struct dns_header *dns = (struct dns_header *)pkt_info->packet; 
    bitset<SIZE_DNS_FLAGS> flags_bits (ntohs(dns->codesFlags));

    struct dns_info *dns_inf = (struct dns_info *)calloc(sizeof(struct dns_info), 1);    
    
    dns_inf->header = dns;
    dns_inf->QR = flags_bits.test(DNS_Resolver::QR);
    dns_inf->RD = flags_bits.test(DNS_Resolver::RD);
    dns_inf->TC = flags_bits.test(DNS_Resolver::TC);
    dns_inf->AA = flags_bits.test(DNS_Resolver::AA);
    dns_inf->RCode = ntohs(dns->codesFlags) & 61440;

    if (dns->totalQuestions > 0) {
        struct dns_question *dns_q = DNS_Resolver::parse_question(dns);
        dns_inf->question = dns_q;
        DNS_Resolver::print_stats(dns_inf);
    }
    
    return dns_inf;
}

void DNS_Resolver::print_labels(vector<string> **labels, int size) {
    vector<string>::iterator itr;
    for (int i=0; i<size; i++) {
        for (itr = labels[i]->begin(); itr < labels[i]->end(); ++itr) {
            fprintf(stderr, "\nchunk: %s", ((string)*itr).c_str());
        }
        fprintf(stderr, "\n");
    }
}

struct dns_question *DNS_Resolver::parse_question(struct dns_header *dns) {
    vector<string> **labels = new vector<string>*[ntohs(dns->totalQuestions)];
    for (int i=0; i<ntohs(dns->totalQuestions); i++) {
        labels[i] = new vector<std::string>;
    }

    struct dns_question *dns_q = (struct dns_question *)calloc(sizeof(struct dns_question), 1);

    int q_ct = ntohs(dns->totalQuestions);
    u_char *q_ptr = ((u_char *)dns) + sizeof(struct dns_header);

    for (int i=0; i<q_ct; i++) { 
        int label_sz = q_ptr[0];
        q_ptr++;
        while (label_sz != 0) {
            string chunk;
            for (int j=0; j<label_sz; j++) {
                if (!((int)*q_ptr == 3))
                    chunk += (char)*q_ptr;
                q_ptr++;
            }
            label_sz = *q_ptr;
            q_ptr++;
            labels[i]->push_back(chunk);
        }     
    }

    memcpy(&dns_q->qtype, q_ptr, sizeof(uint16_t));
    q_ptr += sizeof(uint16_t);
    memcpy(&dns_q->qclass, q_ptr, sizeof(uint16_t));
    dns_q->qnames = labels;
    return dns_q;
}

void DNS_Resolver::print_stats(struct dns_info *info) {
    DNS_Resolver::print_labels(info->question->qnames, ntohs(info->header->totalQuestions));

    fprintf(stderr, "RCode: %d\n", info->RCode);

    if (info->QR) 
        fprintf(stderr, "Response\n");
    else
        fprintf(stderr, "Query\n");

    if (info->AA) 
        fprintf(stderr, "is AA\n");
    else
        fprintf(stderr, "not AA\n");

    if (info->RD) 
        fprintf(stderr, "is RD\n");
    else
        fprintf(stderr, "not RD\n");

    if (info->TC) 
        fprintf(stderr, "is TC\n");
    else 
        fprintf(stderr, "not TC\n");
}

const std::string DNS_Resolver::m_rootServerStrings[] = 
                       {"198.41.0.4", "192.228.79.201", "192.33.4.12", 
                        "128.8.10.90", "192.203.230.10", "192.5.5.241",
                        "192.112.36.4", "128.63.2.53", "192.36.148.17",
                        "192.58.128.30", "193.0.14.129", "199.7.83.42",
                        "202.12.27.33"};

