#ifndef SMART_THREAD_POOL_H
#define SMART_THREAD_POOL_H

#include <pthread.h>
#include <semaphore.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/sysinfo.h>
#endif

typedef struct {
    int port;
    char *target_ip;
    void *scan_config;
} task_t;

typedef struct {
    pthread_t *threads;
    task_t *task_queue;
    int queue_size;
    int queue_front;
    int queue_rear;
    int queue_count;
    int thread_count;
    int shutdown;
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_not_empty;
    pthread_cond_t queue_not_full;
    sem_t *queue_semaphore;
} thread_pool_t;

thread_pool_t* create_thread_pool(int power_level, int total_ports);
void destroy_thread_pool(thread_pool_t *pool);
int add_task(thread_pool_t *pool, int port, char *target_ip, void *scan_config);
void* worker_thread(void *arg);
int get_cpu_count(void);
int calculate_optimal_threads(int power_level, int total_ports);

#endif