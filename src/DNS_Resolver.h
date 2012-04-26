#ifndef DNS_Resolver_H
#define DNS_Resolver_H

#include "structures.h"
#include "Sender_Task.h"

using namespace std;

#define ROOT_SERVERS_LEN 	13
#define NUM_FLAGS 			8

class DNS_Resolver
{
private:
    Sender_Task *m_senderTask;

public:
    enum Flags {
        QR = 1,
        OPCODE = 2,
        AA = 6,
        TC,
        RD,
        RA,
        ZERO,
        RCODE = 12 
    };

    static const string m_rootServerStrings[];
    unsigned long m_rootServerBinary[13];
    DNS_Resolver();
    ~DNS_Resolver();
    void *resolve(struct packet_info *info);
    void print_stats(struct dns_info *info);
    struct dns_question *parse_question(struct dns_header *dns);
    void print_labels(vector<string> **labels, int size);
    struct dns_info *parse_query(struct packet_info *pkt_info);
};

#endif
