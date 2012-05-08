#ifndef structures_H
#define structures_H

#include "net_includes.h"
#include "Queue_Manager.h"
#include <vector>
#include <pthread.h>
#include <string>
#include <stdint.h>
#include <bitset>
#include "Queue_Manager.h"
#include "smartalloc.h"

#define DEBUG 0

/*Ports and Protocols */ 
#define DNS_REQEST 		0
#define DNS_REPLY  		1
#define PROTO_UDP 		17
#define PORT_DNS  		53

/*Packet info and queue size */
#define MAX_DNS_LEN	   512
#define MAX_PACKET_CT	1000
#define SIZE_DNS_FLAGS  16

struct packet_info {
    packet_info() {
        packet = (u_char *)calloc(MAX_DNS_LEN, 1);
        client = (sockaddr_in6 *)calloc(sizeof(sockaddr_in6), 1);
    }    

    ~packet_info() {
        free(client);  
        free(packet);
     }

    unsigned char *packet;
    uint16_t size;
    struct sockaddr_in6 *client;
    int sock;
};

struct sender_args {
    void *queue_manager;
    void *dns_resolver;
}__attribute__((packed));

struct ip_header{
   u_char ver;
   u_char TOS;
   uint16_t ip_len;
   uint16_t ip_id;
   uint16_t frg_offset;
   u_char TTL;
   u_char protocol;
   uint16_t cksum;
   u_char sip[4];
   u_char dip[4];
}__attribute__((packed));

struct udp_header{
	uint16_t sport;
	uint16_t dport;
	uint16_t length;
	uint16_t chksum;
}__attribute__((packed));

struct dns_header{ 
    uint16_t transID;
    uint16_t codesFlags;
    uint16_t totalQuestions;
    uint16_t totalAnswers;
    uint16_t totalAuthority;
    uint16_t totalAdditional;
}__attribute__((packed));

struct dns_question {
    dns_question() {
        qnames = new SMA::vector<SMA::string>();
    }
    ~dns_question() {
        qnames->clear();
        delete qnames;
    }
    
    SMA::vector<SMA::string> *qnames;
    uint16_t qtype;
    uint16_t qclass;
};

struct eth_header {
	uint32_t dmac;
	uint16_t dmacx;
	uint32_t smac;
	uint16_t smacx;
	uint16_t type;
}__attribute__((packed));

enum rcode {
    A       = 1,
    NS      = 2,
    CNAME   = 5,
    SOA     = 6,
    WKS     = 11,
    PTR     = 12,
    MX      = 15,
    AAAA    = 28,
    SRV     = 33,
    A6      = 38,
    ANY     = 255
};

struct dns_record {
    virtual ~dns_record() {}

    SMA::string domain_name;
    uint16_t classt;
    uint16_t type;
    uint32_t ttl; 
    uint16_t data_len;
    uint16_t time_in;
};

struct a_record : dns_record {
    uint32_t ip_address;
};

struct ns_record : dns_record {
    ns_record() {
        name_server = new SMA::vector<SMA::string>();
    }
    ~ns_record() {
        name_server->clear();
        delete name_server;
    }
    SMA::vector<SMA::string> *name_server;
};

struct cname_record : dns_record {
    SMA::string canonical_name;
};

struct soa_record : dns_record {
    char *m_name;
    char *r_name;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t min_ttl;
};

struct ptr_record : dns_record {
    SMA::string ptr_domain;
};

struct mx_record : dns_record { 
    SMA::string mail_exchange;    
};

struct aaaa_record : dns_record {
};

struct dns_info {
    dns_info() {
        questions = new SMA::vector<dns_question *>();
        answers = new SMA::vector<dns_record *>();
        auth_answers = new SMA::vector<dns_record *>();
        add_answers = new SMA::vector<dns_record *>();
    }
    ~dns_info() {
        SMA::vector<dns_question *>::iterator qit;
        for (qit = questions->begin(); qit != questions->end(); ++qit)
            delete (*qit);

        SMA::vector<dns_record *>::iterator it;
        for (it = answers->begin(); it != answers->end(); ++it)
            delete (*it);
        for (it = auth_answers->begin(); it != auth_answers->end(); ++it)
            delete (*it);
        for (it = add_answers->begin(); it != add_answers->end(); ++it)
            delete (*it);
    
        delete questions;
        delete answers;
        delete auth_answers;
        delete add_answers;
    }

    SMA::vector<dns_question *> *questions;
    SMA::vector<dns_record *> *answers;
    SMA::vector<dns_record *> *auth_answers;
    SMA::vector<dns_record *> *add_answers;
    bool QR;
    bool RD;
    bool TC; 
    bool AA;
    uint16_t RCode;
};

#endif 
