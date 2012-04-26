#include "Queue_Manager.h"

Queue_Manager::Queue_Manager() 
    : m_queue(new std::deque<struct packet_info *>())
{
	 if ((m_semaphores[SEM_MUTEX] = sem_open("21ablock", O_CREAT, 0644, 1)) == SEM_FAILED) {
		  perror("Semaphore full initialization");
	 }

 	 if ((m_semaphores[SEM_EMPTY] = sem_open("22balock", O_CREAT, 0644, MAX_PACKET_CT)) == SEM_FAILED) {
	 	  perror("Semaphore full initialization");
	 } 

	 if ((m_semaphores[SEM_FULL] = sem_open("23cblock", O_CREAT, 0644, 0)) == SEM_FAILED) {
		  perror("Semaphore full initialization");
    }  
}

Queue_Manager::~Queue_Manager() {
   sem_close(m_semaphores[SEM_MUTEX]);
	sem_close(m_semaphores[SEM_EMPTY]);
	sem_close(m_semaphores[SEM_FULL]);
}

void Queue_Manager::enque(struct packet_info *pkt_info) {
    sem_wait(m_semaphores[SEM_EMPTY]);
    sem_wait(m_semaphores[SEM_MUTEX]);			

    m_queue->push_front(pkt_info);

    sem_post(m_semaphores[SEM_MUTEX]);
    sem_post(m_semaphores[SEM_FULL]);	
}

struct packet_info *Queue_Manager::deque() {
    sem_wait(m_semaphores[SEM_FULL]);
    sem_wait(m_semaphores[SEM_MUTEX]);

    struct packet_info *pkt_info = m_queue->front();
    m_queue->pop_front();

    sem_post(m_semaphores[SEM_MUTEX]);
    sem_post(m_semaphores[SEM_EMPTY]);

    return pkt_info;
}

uint16_t Queue_Manager::size() {
    return 0;
}
