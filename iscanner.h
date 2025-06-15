#ifndef ISCANNER_H
#define ISCANNER_H

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #define SOCKET_ERROR_VAL SOCKET_ERROR
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define closesocket closesocket
    #define sleep(x) Sleep((x)*1000)
    #define usleep(x) Sleep((x)/1000)
    typedef SOCKET socket_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #define SOCKET_ERROR_VAL -1
    #define INVALID_SOCKET_VAL -1
    #define closesocket close
    typedef int socket_t;
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>

#define MAX_THREADS 65536
#define MAX_PORTS 65535
#define TIMEOUT_MS 1000
#define CONNECT_TIMEOUT 2

typedef struct {
    char target_ip[16];
    int start_port;
    int end_port;
    int power_level;
    int total_ports;
    int scanned_ports;
    int open_ports;
    time_t start_time;
    pthread_mutex_t progress_mutex;
    pthread_mutex_t result_mutex;
    int *open_port_list;
    int open_port_count;
    int max_open_ports;
} scan_config_t;

void print_banner(void);
void print_usage(void);
int parse_arguments(int argc, char *argv[], scan_config_t *config);
void perform_scan(scan_config_t *config);
void cleanup_scan(scan_config_t *config);
void signal_handler(int sig);
void print_progress(scan_config_t *config);
void print_results(scan_config_t *config);

#endif