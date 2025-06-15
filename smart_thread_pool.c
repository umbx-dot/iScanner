#include "smart_thread_pool.h"
#include "iscanner.h"

int get_cpu_count(void) {
#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
#else
    return get_nprocs();
#endif
}

int calculate_optimal_threads(int power_level, int total_ports) {
    int cpu_count = get_cpu_count();
    int base_threads = cpu_count * (power_level == 1 ? 8 : 16);
    
    if (total_ports < 100) {
        return total_ports;
    } else if (total_ports < 1000) {
        return base_threads;
    } else if (total_ports < 10000) {
        return base_threads * 2;
    } else {
        return base_threads * 4;
    }
}

int test_port(const char *ip, int port) {
    socket_t sock;
    struct sockaddr_in addr;
    int result = 0;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET_VAL) return 0;
    
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    fd_set writefds;
    struct timeval timeout;
    
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    
    timeout.tv_sec = 0;
    timeout.tv_usec = TIMEOUT_MS * 1000;
    
    if (select(sock + 1, NULL, &writefds, NULL, &timeout) > 0) {
        int error = 0;
        socklen_t len = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
        result = (error == 0);
    }
    
    closesocket(sock);
    return result;
}

void* worker_thread(void *arg) {
    thread_pool_t *pool = (thread_pool_t*)arg;
    
    while (1) {
        pthread_mutex_lock(&pool->queue_mutex);
        
        while (pool->queue_count == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->queue_not_empty, &pool->queue_mutex);
        }
        
        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->queue_mutex);
            break;
        }
        
        task_t task = pool->task_queue[pool->queue_front];
        pool->queue_front = (pool->queue_front + 1) % pool->queue_size;
        pool->queue_count--;
        
        pthread_cond_signal(&pool->queue_not_full);
        pthread_mutex_unlock(&pool->queue_mutex);
        
        scan_config_t *config = (scan_config_t*)task.scan_config;
        
        if (test_port(task.target_ip, task.port)) {
            pthread_mutex_lock(&config->result_mutex);
            if (config->open_port_count < config->max_open_ports) {
                config->open_port_list[config->open_port_count++] = task.port;
                config->open_ports++;
            }
            pthread_mutex_unlock(&config->result_mutex);
        }
        
        pthread_mutex_lock(&config->progress_mutex);
        config->scanned_ports++;
        pthread_mutex_unlock(&config->progress_mutex);
    }
    
    return NULL;
}

thread_pool_t* create_thread_pool(int power_level, int total_ports) {
    thread_pool_t *pool = malloc(sizeof(thread_pool_t));
    if (!pool) return NULL;
    
    pool->thread_count = calculate_optimal_threads(power_level, total_ports);
    if (pool->thread_count > MAX_THREADS) pool->thread_count = MAX_THREADS;
    
    pool->queue_size = pool->thread_count * 4;
    pool->queue_front = 0;
    pool->queue_rear = 0;
    pool->queue_count = 0;
    pool->shutdown = 0;
    
    pool->threads = malloc(pool->thread_count * sizeof(pthread_t));
    pool->task_queue = malloc(pool->queue_size * sizeof(task_t));
    
    if (!pool->threads || !pool->task_queue) {
        if (pool->threads) free(pool->threads);
        if (pool->task_queue) free(pool->task_queue);
        free(pool);
        return NULL;
    }
    
    pthread_mutex_init(&pool->queue_mutex, NULL);
    pthread_cond_init(&pool->queue_not_empty, NULL);
    pthread_cond_init(&pool->queue_not_full, NULL);
    
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_create(&pool->threads[i], NULL, worker_thread, pool);
    }
    
    return pool;
}

void destroy_thread_pool(thread_pool_t *pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->queue_mutex);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->queue_not_empty);
    pthread_mutex_unlock(&pool->queue_mutex);
    
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    pthread_mutex_destroy(&pool->queue_mutex);
    pthread_cond_destroy(&pool->queue_not_empty);
    pthread_cond_destroy(&pool->queue_not_full);
    
    free(pool->threads);
    free(pool->task_queue);
    free(pool);
}

int add_task(thread_pool_t *pool, int port, char *target_ip, void *scan_config) {
    pthread_mutex_lock(&pool->queue_mutex);
    
    while (pool->queue_count == pool->queue_size && !pool->shutdown) {
        pthread_cond_wait(&pool->queue_not_full, &pool->queue_mutex);
    }
    
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->queue_mutex);
        return 0;
    }
    
    pool->task_queue[pool->queue_rear].port = port;
    pool->task_queue[pool->queue_rear].target_ip = target_ip;
    pool->task_queue[pool->queue_rear].scan_config = scan_config;
    
    pool->queue_rear = (pool->queue_rear + 1) % pool->queue_size;
    pool->queue_count++;
    
    pthread_cond_signal(&pool->queue_not_empty);
    pthread_mutex_unlock(&pool->queue_mutex);
    
    return 1;
}