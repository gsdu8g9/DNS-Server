#ifndef structures_H
#define structures_H

#include "net_includes.h"
#include "Queue_Manager.h"
#include <vector>
#include <string>
#include <stdint.h>
#include <bitset>
#include "Queue_Manager.h"

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
    struct sockaddr_in *client;
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
    uint16_t totalNS;
    uint16_t totalAR;
}__attribute__((packed));

struct dns_question {
    std::vector<std::string> **qnames;
    uint16_t qtype;
    uint16_t qclass;
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
    rcode type;
    std::string domain_name;
    uint16_t ttl;
};

/*struct a_record : dns_record {
    int val;
};*/

#endif 
