#include "iscanner.h"
#include "domain_resolver.h"
#include "smart_thread_pool.h"
#include "add_to_path.h"

static scan_config_t *global_config = NULL;

void print_banner(void) {
    printf("\n");
    printf("┌─────────────────────────────────────────────────────────────┐\n");
    printf("│                      iScanner v2.0                         │\n");
    printf("│                Advanced Port Scanner                        │\n");
    printf("│              Ultra-Fast Multi-threaded Engine              │\n");
    printf("└─────────────────────────────────────────────────────────────┘\n");
    printf("\n");
}

void print_usage(void) {
    printf("Usage: iscanner <target> -range <start> <end> -power <1|2>\n");
    printf("\nParameters:\n");
    printf("  target        IP address or domain name (e.g., 8.8.8.8 or google.com)\n");
    printf("  -range        Port range to scan (1-65535)\n");
    printf("  -power        Thread power level:\n");
    printf("                1 = Half CPU power (conservative)\n");
    printf("                2 = Full CPU power (aggressive)\n");
    printf("\nExamples:\n");
    printf("  iscanner 192.168.1.1 -range 1 1000 -power 1\n");
    printf("  iscanner google.com -range 80 443 -power 2\n");
    printf("  iscanner 8.8.8.8 -range 1 65535 -power 2\n");
    printf("\n");
}

void signal_handler(int sig) {
    if (global_config) {
        printf("\n\n[!] Scan interrupted by user\n");
        print_results(global_config);
        cleanup_scan(global_config);
    }
    exit(0);
}

int parse_arguments(int argc, char *argv[], scan_config_t *config) {
    if (argc != 7) return 0;
    
    char target[256];
    strncpy(target, argv[1], sizeof(target) - 1);
    target[sizeof(target) - 1] = '\0';
    
    if (strcmp(argv[2], "-range") != 0 || strcmp(argv[5], "-power") != 0) return 0;
    
    config->start_port = atoi(argv[3]);
    config->end_port = atoi(argv[4]);
    config->power_level = atoi(argv[6]);
    
    if (config->start_port < 1 || config->start_port > 65535 ||
        config->end_port < 1 || config->end_port > 65535 ||
        config->start_port > config->end_port) return 0;
    
    if (config->power_level < 1 || config->power_level > 2) return 0;
    
    if (is_valid_ip(target)) {
        strncpy(config->target_ip, target, sizeof(config->target_ip) - 1);
        config->target_ip[sizeof(config->target_ip) - 1] = '\0';
    } else {
        if (!resolve_domain_to_ip(target, config->target_ip, sizeof(config->target_ip))) {
            return 0;
        }
    }
    
    config->total_ports = config->end_port - config->start_port + 1;
    config->scanned_ports = 0;
    config->open_ports = 0;
    config->max_open_ports = config->total_ports;
    config->open_port_list = malloc(config->max_open_ports * sizeof(int));
    config->open_port_count = 0;
    
    if (!config->open_port_list) return 0;
    
    pthread_mutex_init(&config->progress_mutex, NULL);
    pthread_mutex_init(&config->result_mutex, NULL);
    
    return 1;
}

void print_progress(scan_config_t *config) {
    pthread_mutex_lock(&config->progress_mutex);
    
    int scanned = config->scanned_ports;
    int total = config->total_ports;
    int open = config->open_ports;
    
    pthread_mutex_unlock(&config->progress_mutex);
    
    double progress = (double)scanned / total * 100.0;
    int bar_width = 50;
    int filled = (int)(progress * bar_width / 100.0);
    
    printf("\r[");
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) printf("█");
        else printf("░");
    }
    printf("] %.1f%% (%d/%d) Open: %d", progress, scanned, total, open);
    fflush(stdout);
}

void print_results(scan_config_t *config) {
    time_t end_time = time(NULL);
    double elapsed = difftime(end_time, config->start_time);
    
    printf("\n\n┌─────────────────────────────────────────────────────────────┐\n");
    printf("│                       SCAN RESULTS                         │\n");
    printf("└─────────────────────────────────────────────────────────────┘\n");
    printf("\nTarget: %s\n", config->target_ip);
    printf("Ports Scanned: %d-%d (%d total)\n", config->start_port, config->end_port, config->total_ports);
    printf("Open Ports: %d\n", config->open_port_count);
    printf("Scan Time: %.2f seconds\n", elapsed);
    printf("Scan Rate: %.0f ports/sec\n", config->total_ports / elapsed);
    
    if (config->open_port_count > 0) {
        printf("\nOpen Ports:\n");
        printf("┌──────────┬─────────────────────────────────────────────────┐\n");
        printf("│   PORT   │                   SERVICE                       │\n");
        printf("├──────────┼─────────────────────────────────────────────────┤\n");
        
        for (int i = 0; i < config->open_port_count; i++) {
            int port = config->open_port_list[i];
            const char *service = "unknown";
            
            switch (port) {
                case 21: service = "ftp"; break;
                case 22: service = "ssh"; break;
                case 23: service = "telnet"; break;
                case 25: service = "smtp"; break;
                case 53: service = "dns"; break;
                case 80: service = "http"; break;
                case 110: service = "pop3"; break;
                case 143: service = "imap"; break;
                case 443: service = "https"; break;
                case 993: service = "imaps"; break;
                case 995: service = "pop3s"; break;
                case 3389: service = "rdp"; break;
                case 5432: service = "postgresql"; break;
                case 3306: service = "mysql"; break;
            }
            
            printf("│   %4d   │ %-47s │\n", port, service);
        }
        printf("└──────────┴─────────────────────────────────────────────────┘\n");
    }
    printf("\n");
}

void perform_scan(scan_config_t *config) {
    printf("\n[+] Initializing scan engine...\n");
    printf("[+] Target: %s\n", config->target_ip);
    printf("[+] Port Range: %d-%d (%d ports)\n", config->start_port, config->end_port, config->total_ports);
    printf("[+] Power Level: %d (%s)\n", config->power_level, 
           config->power_level == 1 ? "Conservative" : "Aggressive");
    
    thread_pool_t *pool = create_thread_pool(config->power_level, config->total_ports);
    if (!pool) {
        fprintf(stderr, "[!] Failed to create thread pool\n");
        return;
    }
    
    printf("[+] Thread Pool: %d threads initialized\n", pool->thread_count);
    printf("[+] Starting scan...\n\n");
    
    config->start_time = time(NULL);
    
    for (int port = config->start_port; port <= config->end_port; port++) {
        add_task(pool, port, config->target_ip, config);
        usleep(100);
    }
    
    while (config->scanned_ports < config->total_ports) {
        print_progress(config);
        usleep(50000);
    }
    
    print_progress(config);
    destroy_thread_pool(pool);
    print_results(config);
}

void cleanup_scan(scan_config_t *config) {
    if (config->open_port_list) {
        free(config->open_port_list);
        config->open_port_list = NULL;
    }
    pthread_mutex_destroy(&config->progress_mutex);
    pthread_mutex_destroy(&config->result_mutex);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (!init_network()) {
        fprintf(stderr, "[!] Failed to initialize network\n");
        return 1;
    }
    
    print_banner();
    
    if (!is_in_path("iscanner")) {
        printf("[+] First run detected - adding to system PATH...\n");
        if (setup_path_integration()) {
            printf("[+] Successfully added to PATH\n");
            printf("[+] You can now run 'iscanner' from anywhere\n\n");
        } else {
            printf("[!] Failed to add to PATH - manual setup required\n\n");
        }
    }
    
    scan_config_t config = {0};
    global_config = &config;
    
    if (!parse_arguments(argc, argv, &config)) {
        print_usage();
        cleanup_network();
        return 1;
    }
    
    perform_scan(&config);
    cleanup_scan(&config);
    cleanup_network();
    
    return 0;
}