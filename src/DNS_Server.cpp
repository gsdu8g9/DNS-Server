#include "DNS_Server.h"

DNS_Server::DNS_Server() 
    : m_queueManager(new Queue_Manager()), m_cacheManager(new Cache_Manager()),
      m_dnsResolver(new DNS_Resolver())
{}
DNS_Server::~DNS_Server() {
    delete m_queueManager;
    delete m_cacheManager;
    delete m_dnsResolver;
}

void DNS_Server::run() {
    pthread_t sender_thread, reciever_thread;
    int tid_sender, tid_reciever;
    struct sender_args sender_args;   

    sender_args.queue_manager = m_queueManager;
    sender_args.dns_resolver = m_dnsResolver;

    tid_reciever = pthread_create(&reciever_thread, NULL, &Reciever_Task::reciever_run, (void*)m_queueManager);
    tid_sender = pthread_create(&sender_thread, NULL, &Sender_Task::sender_run, (void *)&sender_args); 

    pthread_join(reciever_thread, NULL);
    pthread_join(sender_thread, NULL);
}


