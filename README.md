# iScanner v1.2 - Fast Port Scanner

## Features

- **Fast Scanning**:
- **Dual Power Modes**
- **Cross-Platform**
- **Auto PATH Integration**
- **Domain Resolution**
- **Real-time Progress**
- **Smart Thread Management**

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

iscanner 8.8.8.8 -range 1 65535 -power 2

iscanner google.com -range 80 443 -power 1
```

## Performance

iScanner is designed to be significantly faster than traditional port scanners like nmap because it is written in C and has smart threading.


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