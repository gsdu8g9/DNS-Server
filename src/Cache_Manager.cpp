#include "Cache_Manager.h"

Cache_Manager::Cache_Manager() 
{}

Cache_Manager::~Cache_Manager() {
    delete m_recordMap;
}

void Cache_Manager::put(SMA::string key, struct dns_record *value) {
    time_t cur_time = time(NULL);
    value->time_in = cur_time;        
    //m_recordMap->insert(pair<SMA::string, dns_record*>(key, value));
}

struct dns_record *Cache_Manager::get(SMA::string key) {
    //pair<string, dns_record*> mpair = *m_recordMap->find(key);
    struct dns_record *value = NULL;//mpair.second;
    struct dns_record *ret_val = NULL;

    switch (value->type) {
        case A:
            ret_val = (struct a_record*)calloc(sizeof(struct a_record), 1);
            break;
        case NS:
            ret_val = (struct ns_record*)calloc(sizeof(struct ns_record), 1);
            break;
        case CNAME:
            ret_val = (struct cname_record*)calloc(sizeof(struct cname_record), 1);
            break;
        case SOA:
            ret_val = (struct soa_record*)calloc(sizeof(struct soa_record), 1);
            break;
        case PTR:
            ret_val = (struct ptr_record*)calloc(sizeof(struct ptr_record), 1);
            break;
        case MX:
            ret_val = (struct mx_record*)calloc(sizeof(struct mx_record), 1);
            break;
        default:
            ret_val = (struct dns_record*)calloc(sizeof(struct dns_record), 1);
    }

    if (ret_val != NULL) { 
        int dom_len = (int)strlen((const char *)value->domain_name);
        u_char *dom_cpy = (u_char *)calloc(dom_len, 1);
        memcpy(dom_cpy, value->domain_name, dom_len);
        ret_val->domain_name = dom_cpy;
    }

    return (struct dns_record *)0;
}
