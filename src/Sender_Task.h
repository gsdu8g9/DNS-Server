#ifndef Sender_Task_H
#define Sender_Task_H
#include <inttypes.h>
#include <stdint.h>
#include "structures.h"

class Sender_Task 
{
private:
    int m_senderSocketfd;

public:
    ~Sender_Task();
    Sender_Task();

    void query_root(struct packet_info *, struct sockaddr_in *client); 
    static void *sender_run(void *);
};

#endif
