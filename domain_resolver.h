#ifndef DOMAIN_RESOLVER_H
#define DOMAIN_RESOLVER_H

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <netdb.h>
    #include <arpa/inet.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int is_valid_ip(const char *ip);
int resolve_domain_to_ip(const char *domain, char *ip_buffer, size_t buffer_size);
int init_network(void);
void cleanup_network(void);

#endif