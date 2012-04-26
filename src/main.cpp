#include "DNS_Server.h"
#include "Queue_Manager.h"

int main(int argc, char **argv) {
    DNS_Server *dns_application = new DNS_Server();
    dns_application->run();
    delete dns_application;
    return 0;
}

