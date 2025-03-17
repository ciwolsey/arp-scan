# ARP Scanner

A fast and efficient ARP network scanner written in Rust. This tool discovers active hosts on a local network by sending ARP requests and listening for responses.

## Features

- Fast network host discovery using ARP requests
- Automatic network interface detection
- MAC address resolution
- Support for custom IP ranges
- Fast mode for quick-responding networks
- Label support for host identification
- Windows hosts file integration
- Verbose output option

## Prerequisites

- Rust toolchain (rustc, cargo) - [Install from rustup.rs](https://rustup.rs) (for building only)
- Administrator/root privileges (required for raw socket operations)
- Platform's packet capture library must be installed:
  - Windows: Npcap runtime
  - Linux: libpcap
  - macOS: libpcap (pre-installed)

### Platform-Specific Build Requirements

#### Windows
- [Npcap](https://npcap.com/) with SDK is required. Choose ONE of these installation methods:

  **Option 1 (Recommended):**
  - Install Npcap with the "Install Npcap SDK" option selected during installation
  
  **Option 2:**
  - Install Npcap (without SDK)
  - Set `NPCAP_SDK_DIR` environment variable to point to your SDK location
  
  **Option 3:**
  - Install Npcap (without SDK)
  - Install using [vcpkg](https://vcpkg.io/): `vcpkg install npcap:x64-windows`
  
  **Option 4:**
  - Install Npcap (without SDK)
  - Manually download and install the SDK to one of these locations:
    - `C:/Program Files/Npcap/SDK/Lib/x64`
    - `C:/Program Files/NPcapSDK/Lib/x64`
    - `C:/Program Files (x86)/Npcap/SDK/Lib/x64`
    - (see build.rs for all supported paths)

#### Linux
- libpcap development files:
  - Debian/Ubuntu: `sudo apt-get install libpcap-dev`
  - Fedora: `sudo dnf install libpcap-devel`
  - Arch Linux: `sudo pacman -S libpcap`

#### macOS
- libpcap:
  - Using Homebrew: `brew install libpcap`

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ciwolsey/arp-scan
cd arp-scan
```

2. Build the project:
```bash
cargo build --release
```

The compiled binary will be available at `target/release/arp-scan`

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
sudo arp-scan
```

With verbose output:
```bash
sudo arp-scan -v
```

Fast mode:
```bash
sudo arp-scan -f
```

Custom IP range:
```bash
sudo arp-scan -r 192.168.1.0/24
```

With labels:
```bash
sudo arp-scan -l
```

Update Windows hosts file:
```bash
sudo arp-scan -l --add-hosts
```

Preview hosts file changes:
```bash
sudo arp-scan -l --add-hosts --dummy
```

## Output Format

Default output format (tab-separated):
```
IP_ADDRESS    MAC_ADDRESS
```

Example:
```
192.168.0.1   40:0D:10:88:92:90
192.168.0.2   00:12:41:89:3F:4C
```

Verbose mode additionally shows:
- Local IP address
- Network interface being used
- Real-time host discovery
- Scan progress information

## Label Lookup

The scanner supports mapping MAC addresses to custom labels using a `labels.txt` file. When enabled with the `-l` or `--lookup` option, the scanner will read MAC address to label mappings and include them in the output. If the file doesn't exist, the scanner will continue running with the default output format.

### Label File Format

Create a file named `labels.txt` in the same directory as the scanner with entries in the following format:
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

### Output with Labels

When label lookup is enabled, the output format becomes (tab-separated):
```
IP_ADDRESS    MAC_ADDRESS             LABEL
```

Example:
```
192.168.0.1   40:0D:10:88:92:90      Router
192.168.0.2   00:12:41:89:3F:4C      NAS
```

Note: MAC addresses in the labels file are case-insensitive.

## Windows Hosts File Integration

The `--add-hosts` feature allows you to automatically update your Windows hosts file (`C:\Windows\System32\drivers\etc\hosts`) with entries from your `labels.txt` file. Here's how it works:

1. When you run `sudo arp-scan -l --add-hosts`:
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
   sudo arp-scan -l --add-hosts --dummy
   ```
   This will show you exactly what entries would be added or updated.

Note: The `--add-hosts` option requires the `-l` or `--lookup` option to be enabled, as it relies on the hostnames defined in your `labels.txt` file.

## Performance

- Default mode: 2-second scan duration with 10ms packet timeout
- Fast mode: 0.5-second scan duration with 5ms packet timeout

## Notes

- Requires administrator/root privileges due to raw socket operations
- Fast mode may miss slower responding hosts
- Custom range option overrides auto-detected network range

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


