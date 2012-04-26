#ifndef Reciever_Task_H
#define Reciever_Task_H

#include "net_includes.h"
//#include "structures.h"

class Reciever_Task 
{
private:
public:
    ~Reciever_Task();
    Reciever_Task();
    static void *reciever_run(void *args);
    static int create_listener_socket();
    static void print_buf(u_char *buf, int size);
};

#endif
