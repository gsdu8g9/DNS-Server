#ifndef DNS_Resolver_H
#define DNS_Resolver_H

#include "structures.h"
#include "Sender_Task.h"
#include "smartalloc.h"
#include "DNS_Parser.h"

using namespace SMA;

#define ROOT_SERVERS_LEN 	13
#define NUM_FLAGS 			8
class DNS_Resolver
{
private:
    Sender_Task *m_senderTask;
    DNS_Parser *m_dnsParser;
    int m_currentSocket;
    packet_info *m_query;

    packet_info *build_question(dns_record *); 
    bool is_name_ptr(uint16_t *);
    u_char *encode_query_name(vector<string> *, int); 
    int length_query_name(vector<string> *); 
    int resolve(packet_info *);
    bool is_returnable_record(dns_record *); 
    vector<dns_record *> *find_returnable_record(dns_info *); 
    void free_returnable_records(vector <dns_record *> *); 

public:
    DNS_Resolver();
    ~DNS_Resolver();

    enum Flags {
        RCODE   = 0,
        ZERO    = 4,
        RA      = 7,
        RD      = 8,
        TC      = 9,
        AA      = 10,
        OPCODE  = 11,
        QR      = 15 
    };
    
    int create_resolver_binding();
    void handle_query(packet_info *); 
};

#endif
