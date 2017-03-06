//
// Created by lan on 12/20/16.
//
#include "net.h"
#include "debug_msg.h"
#include <sys/poll.h>
#include<errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/tcp.h>
#define BUFFER_SIZE 1024


void fillAddress(const char* address, u_int16_t port, struct sockaddr* addr)
{
    struct sockaddr_in* sa_in;
    sa_in = (struct sockaddr_in*)addr;
    sa_in->sin_family = AF_INET;
    sa_in->sin_port = htons(port);

    if (strlen(address) == 0) {
        sa_in->sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        // Assume we have a simple ipv4 address
        if(inet_pton(AF_INET, address, &sa_in->sin_addr)) return;

        // We need to resolve the address
        struct hostent* host = gethostbyname(address);
        if(!host) {
            err_quit("Failed to resolve address (gethostbyname)!\n");
        }
//        sa_in->sin_addr.s_addr = (uint32_t*)(host->h_addr);
    }
}

const void *get_localip(char *ip)
{
    int sock_get_ip;
    char ipaddr[50];

    struct sockaddr_in *sin;
    struct ifreq ifr_ip;

    if ((sock_get_ip=socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        debug_msg("socket create failse...GetLocalIp!/n");
        return "";
    }

    memset(&ifr_ip, 0, sizeof(ifr_ip));
    strncpy(ifr_ip.ifr_name, "eth0", sizeof(ifr_ip.ifr_name) - 1);

    if(ioctl(sock_get_ip, SIOCGIFADDR, &ifr_ip) < 0) {
        return "";
    }
    sin = (struct sockaddr_in *)&ifr_ip.ifr_addr;
    strcpy(ip, inet_ntoa(sin->sin_addr));

    printf("local ip:%s \n", ip);
    close(sock_get_ip);
}

g_socket *tcp_socket_client(const char* address, u_int16_t port)
{
    int sockfd;
    g_socket *m_socket;

    sockfd = socket (AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        debug_msg("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        return NULL;
    }

    m_socket = (g_socket*)malloc(sizeof(g_socket));
    memset(m_socket, 0, sizeof(g_socket));
    m_socket->sockfd = sockfd;
    fillAddress(address, port, &m_socket->sa);

    if (connect(m_socket->sockfd, &(m_socket->sa), sizeof(m_socket->sa)) < 0) {
        close(m_socket->sockfd);
        free(m_socket);
        debug_msg("connect error: %s(errno: %d)\n", strerror(errno), errno);
        return NULL;
    }

    return m_socket;
}

g_socket *tcp_socket_server(unsigned port)
{
    int sockfd;
    g_socket *m_socket;
    const int on = 1;
    int ret;

    sockfd = socket (AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        debug_msg("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        return NULL;
    }

    m_socket = (g_socket*)malloc(sizeof(g_socket));
    memset(m_socket, 0, sizeof(g_socket));
    m_socket->sockfd = sockfd;
    fillAddress("", port, &m_socket->sa);

    ret = setsockopt(m_socket->sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
    ret = setsockopt(m_socket->sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on));
//    ret = setsockopt(m_socket->sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on));
    if (bind(m_socket->sockfd, &(m_socket->sa), sizeof(m_socket->sa)) != 0) {
        close(m_socket->sockfd);
        free(m_socket);
        debug_msg("bind error: %s(errno: %d)\n", strerror(errno), errno);
        return NULL;
    }

    if (listen(m_socket->sockfd, 10) != 0) {
        close(m_socket->sockfd);
        free(m_socket);
        debug_msg("listen error: %s(errno: %d)\n", strerror(errno), errno);
        return NULL;
    }

    return m_socket;
}

void close_socket(g_socket *socket)
{
    if (socket) {
        if (socket->sockfd > 0) {
            close(socket->sockfd);
        }
        free(socket);
    }
}

int tcp_receive(g_socket *sock, char* buffer, unsigned buf_size, int timeout)
{
    struct pollfd pollfd;
    pollfd.fd = sock->sockfd;
    pollfd.events = POLLIN;
    unsigned int read_index, bytes_read = 0, every_recv = 1024, read_available;

    read_index = 0;
    // TODO:服务端send后再recv会都陷入阻塞,需要结束标记以便知晓数据接受完毕?
    for(;;) {
        int ret = poll(&pollfd, 1, timeout);

        if(ret == 0) {
            debug_msg("time out.");
            break;
        }
        if(ret < 0) {
            err_quit("poll error!");
        }

        if (pollfd.revents & POLLIN || pollfd.revents & POLLPRI) {

            if (ioctl(sock->sockfd, FIONREAD, &read_available) == -1) {
                break;
            }

            if ((read_index + read_available) > buf_size) {
                buffer = (char*)realloc(buffer, (buf_size + read_available) * 2);
                if (!buffer) {
                    err_quit("无法创建新的缓存,已经读了%d字节", bytes_read);
                }

                buf_size = (buf_size + read_available) * 2;
            }
            bytes_read = recv(sock->sockfd, buffer + read_index, read_available, 0);

            read_index += bytes_read;
            if (bytes_read <= 0) {
                debug_msg("receive error or finish received!");

                break;
            }
        }
    }

    buffer[read_index] = '\0';

    return 0;
}

int tcp_send(g_socket *sock, char* buffer, size_t len, int timeout)
{
    return 0;
}

