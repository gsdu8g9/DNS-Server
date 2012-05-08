#include "Queue_Manager.h"
using namespace SMA;

Queue_Manager::Queue_Manager() 
    : m_queue(new std::deque<packet_info *, STLsmartalloc<packet_info *> >())
{
	 if ((m_semaphores[SEM_MUTEX] = sem_open("test1", O_CREAT, 0644, 1)) == SEM_FAILED) {
		  perror("Semaphore full initialization");
	 }

 	 if ((m_semaphores[SEM_EMPTY] = sem_open("test2", O_CREAT, 0644, MAX_PACKET_CT)) == SEM_FAILED) {
	 	  perror("Semaphore full initialization");
	 } 

	 if ((m_semaphores[SEM_FULL] = sem_open("test3", O_CREAT, 0644, 0)) == SEM_FAILED) {
		  perror("Semaphore full initialization");
    }  
}

Queue_Manager::~Queue_Manager() {
    sem_close(m_semaphores[SEM_MUTEX]);
	sem_close(m_semaphores[SEM_EMPTY]);
	sem_close(m_semaphores[SEM_FULL]);
    delete m_queue;
}

void Queue_Manager::enque(struct packet_info *pkt_info) {
    sem_wait(m_semaphores[SEM_EMPTY]);
    sem_wait(m_semaphores[SEM_MUTEX]);			

    m_queue->push_front(pkt_info);

    sem_post(m_semaphores[SEM_MUTEX]);
    sem_post(m_semaphores[SEM_FULL]);
}

int Queue_Manager::deque(struct packet_info **info) {
    sem_wait(m_semaphores[SEM_FULL]);
    sem_wait(m_semaphores[SEM_MUTEX]);
    
    if (m_queue->size() == 0) {
        sem_post(m_semaphores[SEM_MUTEX]);
        return -1;
    }

    *info = (packet_info *)(m_queue->front());
    m_queue->pop_front();

    sem_post(m_semaphores[SEM_MUTEX]);
    sem_post(m_semaphores[SEM_FULL]);

    return 1;
}

uint16_t Queue_Manager::size() {
    return 0;
}
