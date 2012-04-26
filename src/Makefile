#  @author ccarlton
CC=g++

CFLAGS=-Wall -Werror -g -l pthread 

ALL=dns_server

all:  $(ALL)

dns_server: main.o DNS_Server.o Queue_Manager.o Reciever_Task.o Sender_Task.o Cache_Manager.o DNS_Resolver.o
	$(CC) $(CFLAGS) -o $@ $^

main.o: main.cpp
	$(CC) $(CFLAGS) -c $<

DNS_Server.o: DNS_Server.cpp
	$(CC) $(CFLAGS) -c $<

Queue_Manager.o: Queue_Manager.cpp
	$(CC) $(CFLAGS) -c $<

Sender_Task.o: Sender_Task.cpp
	$(CC) $(CFLAGS) -c $<

Reciever_Task.o: Reciever_Task.cpp
	$(CC) $(CFLAGS) -c $<

DNS_Resolver.o: DNS_Resolver.cpp
	$(CC)  $(CFLAGS) -c $<

Cache_Manager.o: Cache_Manager.cpp
	$(CC)  $(CFLAGS) -c $<

clean:
	rm -rf core* *.o *.gch $(ALL)

