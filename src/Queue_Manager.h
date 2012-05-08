#ifndef Queue_Manager_H
#define Queue_Manager_H

#include <deque>
#include "structures.h"
#include "smartalloc.h"

#define NUM_SEM 			3
#define SEM_MUTEX 		    0
#define SEM_EMPTY			1
#define SEM_FULL			2

class Queue_Manager
{
private:

std::deque <struct packet_info *, STLsmartalloc<packet_info *> > *m_queue;
    sem_t *m_semaphores[3];

public: 
    Queue_Manager();
    ~Queue_Manager();

    void enque(struct packet_info *);
    int deque(struct packet_info **);
    uint16_t size();
     
};

#endif
