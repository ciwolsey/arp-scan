# arp-scan

A fast and efficient ARP network scanner written in Rust. This tool scans your local network to discover active hosts and their MAC addresses.

## Features

- Fast network scanning using ARP requests
- Automatic network interface detection
- MAC address resolution
- Support for custom IP ranges
- Fast mode for quick-responding networks
- Label support for host identification
- Windows hosts file integration
- Verbose output option

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/arp-scan.git
cd arp-scan
```

2. Build the project:
```bash
cargo build --release
```

3. Run with administrator privileges:
```bash
# Windows (Run PowerShell as Administrator)
.\target\release\arp-scan.exe

# Linux/macOS
sudo ./target/release/arp-scan
```

## Usage

Basic scan:
```bash
arp-scan
```

With verbose output:
```bash
arp-scan --verbose
```

Fast mode:
```bash
arp-scan --fast
```

Custom IP range:
```bash
arp-scan --range 192.168.1.0/24
```

With labels:
```bash
arp-scan --lookup
```

Update Windows hosts file:
```bash
arp-scan --lookup --add-hosts
```

Preview hosts file changes:
```bash
arp-scan --lookup --add-hosts --dummy
```

## Output Format

The scanner outputs results in a tab-separated format with the following columns:

1. IP Address
2. MAC Address
3. Hostname (if available)
4. Label (if available)

Example output:
```
192.168.0.1         40:0D:10:88:92:90    router.local      Router
192.168.0.10        00:12:41:89:3F:4C    nas.local        NAS
192.168.0.100       00:1B:44:11:3A:B7    printer.local    Printer
192.168.0.101       00:1B:44:11:3A:B8    server.local     Server
```

When labels are not enabled or a host has no label:
```
192.168.0.1         40:0D:10:88:92:90
192.168.0.10        00:12:41:89:3F:4C
```

## Label Support

Create a `labels.txt` file in the same directory as the executable with the following format:
```
MAC_ADDRESS=LABEL=HOSTNAME
```

Example:
```
40:0D:10:88:92:90=Router=router.local
00:12:41:89:3F:4C=NAS=nas.local
```

The HOSTNAME field is optional. If omitted, the entry will be:
```
40:0D:10:88:92:90=Router=
```

## Windows Hosts File Integration

The `--add-hosts` feature allows you to automatically update your Windows hosts file (`C:\Windows\System32\drivers\etc\hosts`) with entries from your `labels.txt` file. Here's how it works:

1. When you run `arp-scan --lookup --add-hosts`:
   - The tool scans your network for active hosts
   - For each discovered host, it checks if its MAC address exists in `labels.txt`
   - If a match is found and the entry has a hostname, it adds or updates an entry in the hosts file
   - The entries are sorted by IP address and properly formatted with aligned columns

2. The hosts file entries are formatted as:
   ```
   192.168.0.1		router.local
   192.168.0.10		nas.local
   ```
   - IP addresses are left-aligned and padded for readability
   - Two tabs separate the IP from the hostname
   - Only entries with hostnames in `labels.txt` are added

3. The tool preserves existing entries in the hosts file that are not managed by arp-scan
   - Only entries matching IPs or hostnames from `labels.txt` are updated
   - Other entries (like localhost, custom entries, etc.) remain unchanged

4. Use the `--dummy` option to preview changes without modifying the hosts file:
   ```bash
   arp-scan --lookup --add-hosts --dummy
   ```
   This will show you exactly what entries would be added or updated.

Note: The `--add-hosts` option requires the `--lookup` option to be enabled, as it relies on the hostnames defined in your `labels.txt` file.

## Requirements

- Rust 1.70 or later
- Administrator/root privileges
- Windows (for hosts file integration) or Linux/macOS

## License

This project is licensed under the MIT License - see the LICENSE file for details.


