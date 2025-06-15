# iScanner v2.0 - Advanced Port Scanner

Ultra-fast multi-threaded port scanner with intelligent thread management and automatic PATH integration.

## Features

- **Ultra-Fast Scanning**: Advanced thread pool with smart load balancing
- **Dual Power Modes**: Conservative (50% CPU) and Aggressive (100% CPU) scanning
- **Cross-Platform**: Full Linux and Windows compatibility
- **Auto PATH Integration**: Automatically adds itself to system PATH on first run
- **Domain Resolution**: Supports both IP addresses and domain names
- **Real-time Progress**: Live progress bar with scan statistics
- **Smart Thread Management**: Automatically calculates optimal thread count
- **Comprehensive Results**: Detailed scan results with service identification

## Compilation

### Linux
```bash
gcc -o iscanner iscanner.c domain_resolver.c smart_thread_pool.c add_to_path.c -lpthread
```

### Windows (MinGW)
```bash
gcc -o iscanner.exe iscanner.c domain_resolver.c smart_thread_pool.c add_to_path.c -lpthread -lws2_32
```

### Windows (MSVC)
```bash
cl iscanner.c domain_resolver.c smart_thread_pool.c add_to_path.c ws2_32.lib -Fe:iscanner.exe
```

## Usage

```bash
iscanner <target> -range <start> <end> -power <1|2>
```

### Parameters
- **target**: IP address or domain name (e.g., 8.8.8.8 or google.com)
- **-range**: Port range to scan (1-65535)
- **-power**: Thread power level
  - `1` = Half CPU power (conservative)
  - `2` = Full CPU power (aggressive)

### Examples
```bash
# Scan common ports on localhost
iscanner 127.0.0.1 -range 1 1000 -power 1

# Aggressive scan of Google's DNS
iscanner 8.8.8.8 -range 1 65535 -power 2

# Scan web ports on domain
iscanner google.com -range 80 443 -power 1
```

## Performance

iScanner is designed to be significantly faster than traditional port scanners like nmap through:
- Intelligent thread pool management
- Optimized socket operations
- Minimal overhead per connection
- Smart timeout handling
- CPU-aware thread scaling

## Installation

On first run, iScanner automatically adds itself to your system PATH. After compilation, simply run the executable and it will be available system-wide.

## Legal Notice

**IMPORTANT**: Read the LICENSE file before using this software. This tool is for authorized security testing only. Users are responsible for compliance with all applicable laws and regulations. Unauthorized port scanning may violate computer crime laws.

## System Requirements

- **Linux**: glibc 2.17+, pthread support
- **Windows**: Windows 7+ or Windows Server 2008+
- **Memory**: 64MB RAM minimum
- **CPU**: Any modern processor (multi-core recommended)

## License

See LICENSE file for complete terms and conditions.