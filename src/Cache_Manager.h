#ifndef Cache_Manager_H
#define Cache_Manager_H

#include "structures.h"
#include "smartalloc.h"
#include <tr1/unordered_map>

using namespace SMA;

class Cache_Manager
{
private:
    std::tr1::unordered_map<SMA::string, struct dns_record *> *m_recordMap;
public: 
    Cache_Manager();
    ~Cache_Manager();
    void put(SMA::string key, struct dns_record *value); 
    struct dns_record *get(SMA::string); 
};

#endif
