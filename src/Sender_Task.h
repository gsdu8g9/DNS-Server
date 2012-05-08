#ifndef Sender_Task_H
#define Sender_Task_H
#include <inttypes.h>
#include <stdint.h>
#include "smartalloc.h"
#include "structures.h"

#define DEFAULT_TIMEOUT     2

class Sender_Task 
{
private:
    int select_call(int, int, int);


public:
    ~Sender_Task();
    Sender_Task();

    int return_response(packet_info *, sockaddr_in *, int ); 
    int query_address(packet_info *, SMA::vector<uint32_t> *, int); 
    int query_root(packet_info *, int); 
    static void *sender_run(void *);
    static const SMA::string m_rootServerStrings[];
};

#endif
