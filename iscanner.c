#include "iscanner.h"
#include "domain_resolver.h"
#include "smart_thread_pool.h"
#include "add_to_path.h"

static scan_config_t *global_config = NULL;


void print_banner(void) {
    // removed it because it was unnecessary you can add one if you want
}

void print_usage(void) {
    printf("Usage: iscanner <target> -range <start> <end> -power <1|2>\n");
    printf("\n");
}

void signal_handler(int sig) {
    if (global_config) {
        printf("\n\nScan interrupted by user\n");
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
    
    printf("\rScanned ");
    printf("%d", scanned);
    printf(" of ");
    printf("%d", total);
    printf(" ports. Found ");
    printf("%d", open);
    printf(" open");
    fflush(stdout);
}

const char* get_service_name(int port) {
    switch (port) {
        case 20: return "ftp-data";
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 67: return "dhcp-server";
        case 68: return "dhcp-client";
        case 69: return "tftp";
        case 79: return "finger";
        case 80: return "http";
        case 88: return "kerberos";
        case 110: return "pop3";
        case 111: return "rpcbind";
        case 119: return "nntp";
        case 123: return "ntp";
        case 135: return "ms-rpc";
        case 137: return "netbios-ns";
        case 138: return "netbios-dgm";
        case 139: return "netbios-ssn";
        case 143: return "imap";
        case 161: return "snmp";
        case 162: return "snmp-trap";
        case 389: return "ldap";
        case 443: return "https";
        case 445: return "smb";
        case 465: return "smtp-ssl";
        case 514: return "syslog";
        case 515: return "lpr";
        case 587: return "smtp-submission";
        case 631: return "ipp";
        case 636: return "ldaps";
        case 873: return "rsync";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1080: return "socks";
        case 1433: return "mssql";
        case 1521: return "oracle";
        case 2049: return "nfs";
        case 2121: return "ftp-proxy";
        case 3128: return "squid-proxy";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5060: return "sip";
        case 5432: return "postgresql";
        case 5900: return "vnc";
        case 6379: return "redis";
        case 8080: return "http-proxy";
        case 8443: return "https-alt";
        case 9100: return "jetdirect";
        case 27017: return "mongodb";
        default: return "unknown"; // you can add more here btw 
    }
}

void print_results(scan_config_t *config) {
    time_t end_time = time(NULL);
    double elapsed = difftime(end_time, config->start_time);
    
    printf("\n\nTarget ");
    printf("%s", config->target_ip);
    printf("\n");
    printf("Scanned ");
    printf("%d", config->total_ports);
    printf(" ports in ");
    printf("%.0f", elapsed);
    printf(" seconds\n");
    
    if (config->open_port_count > 0) {
        printf("Open ports:\n");
        
        for (int i = 0; i < config->open_port_count; i++) {
            int port = config->open_port_list[i];
            const char *service = get_service_name(port);
            printf("%d", port);
            printf(" ");
            printf("%s", service);
            printf("\n");
        }
    } else {
        printf("No open ports found\n");
    }
    printf("\n");
}

void perform_scan(scan_config_t *config) {
    printf("\nInitializing scan engine...\n");
    printf("Target: %s\n", config->target_ip);
    printf("Port Range: ");
    printf("%d", config->start_port);
    printf(" to ");
    printf("%d", config->end_port);
    printf(" total ");
    printf("%d", config->total_ports);
    printf(" ports\n");
    if (config->power_level == 1) {
        printf("Power Level: 1 Conservative\n");
    } else {
        printf("Power Level: 2 Aggressive\n");
    }
    
    thread_pool_t *pool = create_thread_pool(config->power_level, config->total_ports);
    if (!pool) {
        fprintf(stderr, "Failed to create thread pool\n");
        return;
    }
    
    printf("Thread Pool: ");
    printf("%d", pool->thread_count);
    printf(" threads initialized\n");
    printf("Starting scan...\n\n");
    
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
        fprintf(stderr, "Failed to initialize network\n");
        return 1;
    }
    
    print_banner();
    
    if (!is_in_path("iscanner")) {
        printf("First run detected - adding to system PATH...\n");
        if (setup_path_integration()) {
            printf("Successfully added to PATH\n");
            printf("You can now run 'iscanner' from anywhere\n\n");
        } else {
            printf("Failed to add to PATH - manual setup required\n\n");
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