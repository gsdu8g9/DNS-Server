#ifndef Cache_Manager_H
#define Cache_Manager_H

#include "structures.h"
#include <tr1/unordered_map>

using namespace std;

class Cache_Manager
{
private:
  //  std::unordered_map<std::string, struct dns_record *> m_recordMap;
    sem_t *m_mutex;
public: 
    Cache_Manager();
    ~Cache_Manager();
    void put(string key, struct dns_record *value); 
    struct dns_record *get(string); 
};

#endif
