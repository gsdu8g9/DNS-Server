#include "Cache_Manager.h"

Cache_Manager::Cache_Manager() 
    : m_mutex (sem_open("cache_lock24", O_CREAT, 0644, 1)) 
{
    if (m_mutex == SEM_FAILED) 
        perror("Semaphore mutex initialization failed");
}

Cache_Manager::~Cache_Manager() {
}

void Cache_Manager::put(std::string key, struct dns_record *value) {
    sem_wait(m_mutex);
    
    

    sem_post(m_mutex);
}

struct dns_record *Cache_Manager::get(std::string key) {
    sem_wait(m_mutex);

    struct dns_record *value = NULL;
    struct dns_record *ret_val = NULL;
    printf("%p", ret_val);
    switch (value->type) {
        case A:
         //   ret_val = (struct dns_record *)memcpy(record, ret_val, sizeof(dns_record));
            break;
        default:
            break;         
    } 

    sem_post(m_mutex);
    return (struct dns_record *)0;
}
