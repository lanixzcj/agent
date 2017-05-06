//
// Created by lan on 12/20/16.
//

#ifndef UNTITLED_NET_H
#define UNTITLED_NET_H

#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug_msg.h"
#include <sys/poll.h>
#include<errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/tcp.h>
#define G_SOCKADDR_IN(s) (*((struct sockaddr_in*) &s))

typedef struct
{
    int sockfd;
    struct sockaddr sa;
} g_socket;

g_socket *tcp_socket_client(const char* address, u_int16_t port);
g_socket *tcp_socket_server(unsigned port);
void close_socket(g_socket *socket);
int tcp_receive(g_socket *sock, char* buffer, unsigned buf_size, int timeout);
const void *get_localip(char *ip);

#endif //UNTITLED_NET_H
