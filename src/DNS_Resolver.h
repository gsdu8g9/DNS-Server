#ifndef DNS_Resolver_H
#define DNS_Resolver_H

#include "structures.h"
#include "Sender_Task.h"
#include "smartalloc.h"

using namespace SMA;

#define ROOT_SERVERS_LEN 	13
#define NUM_FLAGS 			8
#define DEFAULT_TIMEOUT     2
class DNS_Resolver
{
private:
    Sender_Task *m_senderTask;
    int m_currentSocket;
    struct sockaddr_in6 *m_currentAddr;

    vector<string> **build_label_vector(int); 
    dns_info *parse_response(packet_info *); 
    u_char *parse_question(dns_header *, vector<dns_question *> *);
    u_char *parse_answers(dns_header *, u_char *, vector<dns_record*> *, vector<dns_record *> *); 
    bool is_name_ptr(uint16_t *);
    u_char *parse_label(dns_header *, vector<string> *, u_char *);
    
public:
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

    int select_call(int, int); 
    static const string m_rootServerStrings[];
    unsigned long m_rootServerBinary[13];
    DNS_Resolver();
    ~DNS_Resolver();
    void *resolve(packet_info *);
    void print_stats(dns_info *);
    dns_question *parse_question(dns_header *);
    void print_labels(vector<string> **, int);
    int create_resolver_binding();
    void setCurrentAddr(struct sockaddr_in6 *);
    void build_empty_cache_response();
    u_char *build_cache_response(dns_record *); 

};

#endif
