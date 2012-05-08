#ifndef DNS_Parser_H
#define DNS_Parser_H

#include "structures.h"
#include "Reciever_Task.h"
#include "smartalloc.h"

using namespace SMA;

class DNS_Parser
{
private:
    rcode get_record_type(uint16_t *); 
    vector<string> **build_label_vector(int); 
    u_char *parse_question(dns_header *, vector<dns_question *> *);
    void parse_answers(dns_header *, u_char *, vector<dns_record*> *, vector<dns_record *> *, vector<dns_record *> *); 
    bool is_name_ptr(uint16_t *);
    dns_record *allocate_record(uint16_t *); 
    u_char *build_record(u_char *, dns_record *, string, dns_header *); 
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

    DNS_Parser();
    ~DNS_Parser();
    void print_stats(dns_info *);
    dns_info *parse_response(packet_info *); 
    void print_labels(vector<string> *); 
};

#endif
