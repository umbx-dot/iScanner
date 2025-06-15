#include "domain_resolver.h"

int init_network(void) {
#ifdef _WIN32
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
#else
    return 1;
#endif
}

void cleanup_network(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

int resolve_domain_to_ip(const char *domain, char *ip_buffer, size_t buffer_size) {
    struct addrinfo hints, *result;
    int status;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    status = getaddrinfo(domain, NULL, &hints, &result);
    if (status != 0) {
        return 0;
    }
    
    struct sockaddr_in *addr_in = (struct sockaddr_in *)result->ai_addr;
    const char *ip_str = inet_ntoa(addr_in->sin_addr);
    
    if (ip_str && strlen(ip_str) < buffer_size) {
        strcpy(ip_buffer, ip_str);
        freeaddrinfo(result);
        return 1;
    }
    
    freeaddrinfo(result);
    return 0;
}