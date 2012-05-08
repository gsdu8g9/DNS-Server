#include "DNS_Parser.h"
#include <sys/time.h>

using namespace SMA;

DNS_Parser::DNS_Parser(){}
DNS_Parser::~DNS_Parser(){}

struct dns_info *DNS_Parser::parse_response(struct packet_info *pkt_info) {
    dns_header *dns = (struct dns_header *)pkt_info->packet; 
    uint16_t flags_bits = ntohs(dns->codesFlags);

    struct dns_info *dns_inf = new dns_info();    
    
    dns_inf->QR = flags_bits & (1 << DNS_Parser::QR);
    dns_inf->RD = flags_bits & (1 << DNS_Parser::RD);
    dns_inf->TC = flags_bits & (1 << DNS_Parser::TC);
    dns_inf->AA = flags_bits & (1 << DNS_Parser::AA);
    dns_inf->RCode = ntohs(dns->codesFlags) & 61440;
    
    u_char *answer_ptr = NULL; 
    if (ntohs(dns->totalQuestions) > 0) {
        answer_ptr = DNS_Parser::parse_question(dns, dns_inf->questions);
    } else {
       answer_ptr = (u_char *)dns + sizeof(dns_header);
    }

    if (dns->totalAnswers > 0 || dns->totalAuthority > 0) {
        DNS_Parser::parse_answers(dns, answer_ptr, dns_inf->answers, dns_inf->auth_answers, dns_inf->add_answers); 
    }

    return dns_inf;
}

void DNS_Parser::print_labels(vector<string> *labels) {
    vector<string>::iterator itr;
    for (itr = labels->begin(); itr < labels->end(); ++itr) {
        fprintf(stderr, "\nchunk: %s", ((string)*itr).c_str());
    }
}

u_char *DNS_Parser::parse_label(dns_header *dns, vector<string> *labels, u_char *ptr) {
    if (DEBUG) {
        fprintf(stderr, "\nparse_label_buf: \n");
        Reciever_Task::print_buf(ptr, 2);
    }
    if (strlen( (char *)ptr) == 0) {
        labels->push_back("");
        return ++ptr;
    }

    if ( DNS_Parser::is_name_ptr((uint16_t *)ptr) ) {
        uint16_t flags;
        memcpy(&flags, ptr, 2);
        uint16_t ptr_loc = (ntohs(flags)) & 255;
        DNS_Parser::parse_label(dns, labels, (u_char *)(&(dns->transID))+ptr_loc); 
        ptr += sizeof(uint16_t);
    } else {
        int label_size = ptr[0];
        ptr++;

        while (label_size != 0) {
            string chunk;
            for (int j=0; j<label_size; j++) {
                if (!((int)*ptr == 3))
                    chunk += (char)*ptr;
                ptr++;
            }
            labels->push_back(chunk);
            label_size = *ptr;
            if (DNS_Parser::is_name_ptr((uint16_t *)ptr)) {

                uint16_t flags;
                memcpy(&flags, ptr, 2);
                uint16_t ptr_loc = (ntohs(flags)) & 255;
                DNS_Parser::parse_label(dns, labels, (u_char *)(&(dns->transID))+ptr_loc); 
                break;
            }
            ptr++;
        }
    }
    return ptr;   
}

u_char *DNS_Parser::parse_question(dns_header *dns, vector<dns_question *> *qs) {
    dns_question *dns_q = NULL;

    u_char *q_ptr = ((u_char *)dns) + sizeof(dns_header);
    int question_count = ntohs(dns->totalQuestions);

    for (int i=0; i<question_count; i++) { 
        dns_q = new dns_question(); 
        
        q_ptr = DNS_Parser::parse_label(dns, dns_q->qnames, q_ptr); 
        memcpy(&dns_q->qtype, q_ptr, sizeof(uint16_t));
        q_ptr += sizeof(uint16_t);
        memcpy(&dns_q->qclass, q_ptr, sizeof(uint16_t));
        q_ptr += sizeof(uint16_t);
     
        qs->push_back(dns_q);
    }
    return q_ptr;
}

void DNS_Parser::parse_answers(dns_header *dns, u_char *answer_ptr, vector<dns_record *> *answers, vector<dns_record *> *auth_answers, vector<dns_record *> *add_answers) {
    int answer_count = ntohs(dns->totalAnswers);
    int auth_count = ntohs(dns->totalAuthority);
    int additional_count = ntohs(dns->totalAdditional);
    int question_count = ntohs(dns->totalQuestions);

    if (DEBUG) {
        fprintf(stderr, "Total Questions: %d\n", question_count);
        fprintf(stderr, "Total Answers: %d\n", answer_count);
        fprintf(stderr, "Total Auth Answers: %d\n", auth_count);
        fprintf(stderr, "Total Additional Answers: %d\n\n", additional_count);
    }

    vector<string> *name = new vector<string>();
    for (int i=0; i<answer_count; i++) {
        answer_ptr = DNS_Parser::parse_label(dns, name, answer_ptr);
        dns_record *rec = (dns_record *)DNS_Parser::allocate_record((uint16_t *)answer_ptr);
        
        if (name->size() > 0 && rec != 0) {
            answer_ptr = DNS_Parser::build_record(answer_ptr, rec, name->front(), dns);
            answers->push_back(rec); 
        } 
        name->clear();
    }

    for (int i=0; i<auth_count; i++) {
        answer_ptr = DNS_Parser::parse_label(dns, name, answer_ptr);

        if (name->size() > 0) {
            dns_record *rec = (dns_record *)DNS_Parser::allocate_record((uint16_t *)answer_ptr);
            answer_ptr = DNS_Parser::build_record(answer_ptr, rec, name->front(), dns);
            auth_answers->push_back(rec); 
        }  
 
        name->clear();
    }

    for (int i=0; i<additional_count; i++) {
        answer_ptr = DNS_Parser::parse_label(dns, name, answer_ptr);
       
        if (name->size() > 0 ) {
            dns_record *rec = (dns_record *)DNS_Parser::allocate_record((uint16_t *)answer_ptr);
            if (rec == NULL)
                break;
            answer_ptr = DNS_Parser::build_record(answer_ptr, rec, name->front(), dns);
            add_answers->push_back(rec);
        } 

        name->clear();
    }

    delete name;
}

u_char *DNS_Parser::build_record(u_char *ptr, dns_record *rec, string name, dns_header *dns) {
    rec->domain_name.assign(name.c_str());

    memcpy(&rec->type, ptr, sizeof(uint16_t));
    ptr += sizeof(uint16_t);
    memcpy(&rec->classt, ptr, sizeof(uint16_t));
    ptr += sizeof(uint16_t);
    memcpy(&rec->ttl, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(&rec->data_len, ptr, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    switch (ntohs(rec->type)) {
        case A:
            memcpy(&(((a_record *)rec)->ip_address), ptr, sizeof(uint32_t));
            break;
        case NS: 
            DNS_Parser::parse_label(dns, ((ns_record *)rec)->name_server, ptr);
            break;
        case CNAME:
            break;
        case SOA:
            break;
        case PTR:
            break;
        case MX:
            break;
        default:
            break; 
    }

    return ptr + ntohs(rec->data_len); 
} 

dns_record *DNS_Parser::allocate_record(uint16_t *type_ptr) {
    uint16_t type = ntohs(*type_ptr);
    dns_record *ret_type = NULL;
    switch (type) {
        case A:
            ret_type = (dns_record *) new a_record();
            break;
        case NS:
            ret_type = (dns_record *) new ns_record();
            break;
        case CNAME:
            ret_type = (dns_record *) new cname_record();
            break;
        case SOA:
            ret_type = (dns_record *) new soa_record();
            break;
        case PTR:
            ret_type = (dns_record *) new ptr_record();
            break;
        case MX:
            ret_type = (dns_record *) new mx_record();
            break;
        case AAAA:
            ret_type = (dns_record *) new aaaa_record();
            break;
        default:
            break; 
    }
    return ret_type;
}


bool DNS_Parser::is_name_ptr(uint16_t *name) {
    uint16_t flags = ntohs(*name);
    if ( (flags & (1<<14)) ) 
        if ( (flags & (1<<15)) ) 
            return true; 
    return false;
}

void DNS_Parser::print_stats(dns_info *info) {
    for (vector<dns_question *>::iterator it = info->questions->begin(); it != info->questions->end(); ++it) {
        fprintf(stderr, "\nQuestion: \n");
        DNS_Parser::print_labels(((dns_question *)*it)->qnames);
    }

    for (vector<dns_record *>::iterator it = info->answers->begin(); it != info->answers->end(); ++it) {
        fprintf(stderr, "\nAnswer: \n");
        fprintf(stderr, "    name: %s\n", (char *)((dns_record *)(*it)->domain_name.c_str()));
    }
 
    for (vector<dns_record *>::iterator it = info->auth_answers->begin(); it !=info->auth_answers->end(); ++it) {
        fprintf(stderr, "\nAuth Answer: \n");
        fprintf(stderr, "    name: %s\n", (char *)((dns_record *)(*it)->domain_name.c_str()));
    
        if (ntohs(((dns_record *)*it)->type) == NS) {
            fprintf(stderr, "    ns:\n");
            DNS_Parser::print_labels( ((ns_record *)*it)->name_server);    
        }
    }
    
    fprintf(stderr, "\nSizes: %d, %d, %d\n", (int)info->questions->size(), (int)(info->answers->size()), (int)info->auth_answers->size());    

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
