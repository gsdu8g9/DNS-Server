#include "DNS_Resolver.h"
#include "Reciever_Task.h"
#include <sys/select.h>
#include <sys/time.h>

using namespace SMA;

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
    uint16_t flags_order = ntohs(dns->codesFlags);

    struct dns_info *dns_inf;      
    dns_inf = DNS_Resolver::parse_response(pkt_info);
    Reciever_Task::print_buf(pkt_info->packet, pkt_info->size);   
    
    if ((flags_order & (1<<DNS_Resolver::QR))) {
         
        free(dns_inf);
        free(pkt_info->packet);
        fprintf(stderr, "Got response, returning\n");     
    } else {
        if (!(flags_order & (1<<DNS_Resolver::RD))) {
            fprintf(stderr, "Got iterative query!\n");     
            return (void *)-1;
        } else {
            DNS_Resolver::setCurrentAddr(pkt_info->client);
            for (int i=ROOT_SERVERS_LEN-1; i>=0; i--) { 
                /* Store the return address for when the query is completely resolved */
                m_senderTask->query_root(pkt_info, (char *)m_rootServerStrings[i].c_str(), m_currentSocket);   
                
                if(select_call(DEFAULT_TIMEOUT, 0)) {
                    free(dns_inf);
                    free(pkt_info->packet);
                     
                    pkt_info->packet = (u_char *)calloc(MAX_DNS_LEN, 1);
                    socklen_t client_len = sizeof(*pkt_info->client);
                    if ((pkt_info->size = recvfrom(m_currentSocket, pkt_info->packet,  MAX_DNS_LEN, 0, (struct sockaddr *)pkt_info->client, &client_len)) == -1) {
                        return (void *)-1;
                    }
                    fprintf(stderr, "recursing");
                    DNS_Resolver::resolve(pkt_info); 
             
                    break;
                } 
            } 
        }
    }

    return (void *)0;
}

void build_empty_cache_response() {}

u_char *build_cache_response(struct dns_response *response) {
    return (u_char *)-1;
}

void DNS_Resolver::setCurrentAddr(struct sockaddr_in6 *in) {
    this->m_currentAddr = in;
}

int DNS_Resolver::select_call(int seconds, int useconds) {
   //setup vars
   static struct timeval timeout;
   fd_set fdvar;

   //setup timeout
   timeout.tv_sec = seconds;
   timeout.tv_usec = 0;
   FD_ZERO(&fdvar);
   FD_SET(m_currentSocket, &fdvar);

   return (select(m_currentSocket+1, (fd_set *)&fdvar, (fd_set *)0, (fd_set *)0, &timeout));

}


int DNS_Resolver::create_resolver_binding() {
    int socketfd;
    struct sockaddr_in saddr;
    uint32_t len = sizeof(saddr);

    if ((socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(stderr, "Error creating socket!\n");
        return -1;
    }

    memset((char *) &saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(0);
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(socketfd, (struct sockaddr *)&saddr, sizeof(saddr))==-1) {
        fprintf(stderr, "xbind");
        return -1;
    }

    //print the port
    if (getsockname(socketfd,(struct sockaddr *)&saddr, &len) < 0) {
        perror("getsockname call");
        exit(-1);
    }

    //fprintf(stderr, "Second socket bound to port: %d\n", ntohs(saddr.sin_port));
    m_currentSocket = socketfd;

    return 0;
}

struct dns_info *DNS_Resolver::parse_response(struct packet_info *pkt_info) {
    struct dns_header *dns = (struct dns_header *)pkt_info->packet; 
    uint16_t flags_bits = ntohs(dns->codesFlags);

    struct dns_info *dns_inf = (struct dns_info *)calloc(sizeof(struct dns_info), 1);    
    
    dns_inf->header = dns;
    dns_inf->QR = flags_bits & (1 << DNS_Resolver::QR);
    dns_inf->RD = flags_bits & (1 << DNS_Resolver::RD);
    dns_inf->TC = flags_bits & (1 << DNS_Resolver::TC);
    dns_inf->AA = flags_bits & (1 << DNS_Resolver::AA);
    dns_inf->RCode = ntohs(dns->codesFlags) & 61440;

    if (dns->totalQuestions > 0) {

    vector<dns_question *> *questions = new vector<dns_question *>(); 
    vector<dns_record *> *answers = new vector<dns_record *>();
    vector<dns_record *> *auth_answers = new vector<dns_record *>(); 
    u_char *answer_ptr = DNS_Resolver::parse_question(dns, questions);
    u_char *auth_ptr = DNS_Resolver::parse_answers(dns, answer_ptr, answers, auth_answers); 
    auth_ptr++;   
     //dns_inf->question = dns_q;
     // DNS_Resolver::print_stats(dns_inf);
    }
    
    return dns_inf;
}

void DNS_Resolver::print_labels(SMA::vector<SMA::string> **labels, int size) {
    vector<string>::iterator itr;
    for (int i=0; i<size; i++) {
        for (itr = labels[i]->begin(); itr < labels[i]->end(); ++itr) {
            fprintf(stderr, "\nchunk: %s", ((string)*itr).c_str());
        }
        fprintf(stderr, "\n");
    }
}

vector<string> **DNS_Resolver::build_label_vector(int num_questions) {
    vector<string> **labels = new vector<string>*[num_questions];
    for (int i=0; i<num_questions; i++) {
        labels[i] = new vector<string>;
    }
    return labels;
} 

u_char *DNS_Resolver::parse_label(dns_header *dns, vector<string> *labels, u_char *ptr) {
    if ( DNS_Resolver::is_name_ptr((uint16_t *)ptr) ) {
        uint16_t flags;
        memcpy(&flags, ptr, 2);
        uint16_t ptr_loc = (ntohs(flags)) & 255;
        u_char *temp_ptr = DNS_Resolver::parse_label(dns, labels, (u_char *)(&(dns->transID))+ptr_loc); 
        temp_ptr++; 
        fprintf(stderr, "Got a ptr val %d\n", ptr_loc);
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
            label_size = *ptr;
            ptr++;
            labels->push_back(chunk);
            //fprintf(stderr, "Size of labels is: %d\n", (int)labels->size());
            //fprintf(stderr, "\n\nLabel Content: %s\n\n", (char *)((labels->front()).c_str()));
        }
    }
    return ptr;   
}

u_char *DNS_Resolver::parse_question(dns_header *dns, vector<dns_question *> *qs) {
    dns_question *dns_q = NULL;
    vector<string> **labels = NULL;
    int question_count = ntohs(dns->totalQuestions);
    u_char *q_ptr = ((u_char *)dns) + sizeof(dns_header);

    for (int i=0; i<question_count; i++) { 
        //int label_size = q_ptr[0];
        
        dns_q = (dns_question *)calloc(sizeof(dns_question), 1);
        labels = DNS_Resolver::build_label_vector(question_count);
        
        q_ptr = DNS_Resolver::parse_label(dns, labels[i], q_ptr); 

        memcpy(&dns_q->qtype, q_ptr, sizeof(uint16_t));
        q_ptr += sizeof(uint16_t);
        memcpy(&dns_q->qclass, q_ptr, sizeof(uint16_t));
        dns_q->qnames = labels;
        q_ptr += sizeof(uint16_t);
     
        qs->push_back(dns_q);
        DNS_Resolver::print_labels(dns_q->qnames, 1);
    }
    return q_ptr;
}

u_char *DNS_Resolver::parse_answers(dns_header *dns, u_char *answer_ptr, vector<dns_record *> *answers, vector<dns_record *> *auth_answers) {
    int answer_count = ntohs(dns->totalAnswers);
    int auth_count = ntohs(dns->totalAuthority);
    fprintf(stderr, "Total Answers: %d\n", answer_count);
    fprintf(stderr, "Total Auth Answers: %d\n\n", auth_count);
    
    Reciever_Task::print_buf(answer_ptr, 10);    

    fprintf(stderr, "\n");

    vector<string> *name = NULL;
    for (int i=0; i<answer_count; i++) {
        vector<string> *name = new vector<string>();
        answer_ptr = DNS_Resolver::parse_label(dns, name, answer_ptr);
        
    }

    for (int i=0; i<auth_count; i++) {
        vector<string> *name = new vector<string>();
        answer_ptr = DNS_Resolver::parse_label(dns, name, answer_ptr);
        
        break;
    }

    return (u_char *)1;
}

bool DNS_Resolver::is_name_ptr(uint16_t *name) {
    uint16_t flags = ntohs(*name);
    if ( (flags & (1<<14)) ) 
        if ( (flags & (1<<15)) ) 
            return true; 
    return false;
}

void DNS_Resolver::print_stats(dns_info *info) {
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

const SMA::string DNS_Resolver::m_rootServerStrings[] = 
                       {"198.41.0.4", "192.228.79.201", "192.33.4.12", 
                        "128.8.10.90", "192.203.230.10", "192.5.5.241",
                        "192.112.36.4", "128.63.2.53", "192.36.148.17",
                        "192.58.128.30", "193.0.14.129", "199.7.83.42",
                        "202.12.27.33"};

