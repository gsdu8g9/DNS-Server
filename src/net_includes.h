#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <getopt.h>
#include <features.h>
#include <errno.h>

#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <semaphore.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>


