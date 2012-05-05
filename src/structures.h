#ifndef structures_H
#define structures_H

#include "net_includes.h"
#include "Queue_Manager.h"
#include <vector>
#include <string>
#include <stdint.h>
#include <bitset>
#include "Queue_Manager.h"
#include "smartalloc.h"

/*Ports and Protocols */ 
#define DNS_REQEST 		0
#define DNS_REPLY  		1
#define PROTO_UDP 		17
#define PORT_DNS  		53

/*Packet info and queue size */
#define MAX_DNS_LEN	   512
#define MAX_PACKET_CT	100
#define SIZE_DNS_FLAGS  16

struct packet_info {
    unsigned char *packet;
    uint16_t size;
    struct sockaddr_in6 *client;
}__attribute__((packed));

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
    SMA::vector<SMA::string> **qnames;
    uint16_t qtype;
    uint16_t qclass;
}__attribute__((packed));

struct dns_answer {
    SMA::vector<SMA::string> **qnames;
}__attribute__((packed));

struct dns_info {
    struct dns_header   *header;
    struct dns_question *question;
    bool QR;
    bool RD;
    bool TC; 
    bool AA;
    uint16_t RCode;
}__attribute__((packed));


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
    SRV     = 33,
    A6      = 38,
    ANY     = 255
};

struct dns_record {
    u_char *domain_name;
    uint16_t classt;
    rcode type;
    uint16_t ttl; 
    uint16_t data_len;

    uint16_t time_in;
};

struct a_record : dns_record {
    uint32_t ip_address;
};

struct ns_record : dns_record {
    char *name_server_name;
};

struct cname_record : dns_record {
    char *canonical_name;
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
    char *ptr_domain;
};

struct mx_record : dns_record { 
    char *mail_exchange;    
};


#endif 
