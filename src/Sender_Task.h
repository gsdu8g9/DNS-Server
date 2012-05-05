#ifndef Sender_Task_H
#define Sender_Task_H
#include <inttypes.h>
#include <stdint.h>
#include "smartalloc.h"
#include "structures.h"

class Sender_Task 
{
private:

public:
    ~Sender_Task();
    Sender_Task();

    void query_root(struct packet_info *, char *address, int sock); 
    static void *sender_run(void *);
};

#endif
