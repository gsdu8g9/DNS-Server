#ifndef DNS_Server_H
#define DNS_Server_H

#include "structures.h"
#include "smartalloc.h"
#include "Cache_Manager.h"
#include "Reciever_Task.h"
#include "Sender_Task.h"
#include "DNS_Resolver.h"
#include <pthread.h>

class DNS_Server
{
private:
    Queue_Manager *m_queueManager;
    Cache_Manager *m_cacheManager;
    DNS_Resolver  *m_dnsResolver;
public:
    DNS_Server();
    ~DNS_Server();
    void run();
};

#endif
