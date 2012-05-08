#  @author ccarlton
CP=g++
CC=gcc
CFLAGS=-Wall -Werror -c -pthread
CPFLAGS=-Wall -Werror -g -pthread 

ALL=dns_server

all:  $(ALL)

dns_server: main.o smartalloc.o DNS_Server.o Queue_Manager.o Reciever_Task.o Sender_Task.o Cache_Manager.o DNS_Resolver.o DNS_Parser.o
	$(CP) $(CPFLAGS) -o $@ $^

main.o: main.cpp
	$(CP) $(CPFLAGS) -c $<

DNS_Server.o: DNS_Server.cpp
	$(CP) $(CPFLAGS) -c $<

Queue_Manager.o: Queue_Manager.cpp
	$(CP) $(CPFLAGS) -c $<

Sender_Task.o: Sender_Task.cpp
	$(CP) $(CPFLAGS) -c $<

Reciever_Task.o: Reciever_Task.cpp
	$(CP) $(CPFLAGS) -c $<

DNS_Resolver.o: DNS_Resolver.cpp
	$(CP)  $(CPFLAGS) -c $<

Cache_Manager.o: Cache_Manager.cpp
	$(CP)  $(CPFLAGS) -c $<

DNS_Parser.o: DNS_Parser.cpp
	$(CP)  $(CPFLAGS) -c $<

smartalloc.o: smartalloc.c
	$(CC)  $(CFLAGS) -c $<

clean:
	rm -rf core* *.o *.gch $(ALL)

