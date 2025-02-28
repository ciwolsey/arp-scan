# ARP Scanner

A fast and efficient ARP network scanner written in Rust. This tool discovers active hosts on a local network by sending ARP requests and listening for responses.

## Features

- Fast network host discovery using ARP requests
- Automatic network interface detection

## Prerequisites

- Rust toolchain (rustc, cargo) - [Install from rustup.rs](https://rustup.rs)
- Administrator/root privileges (required for raw socket operations)

### Platform-Specific Requirements

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

## Usage

Basic scan (automatically detects network):
```bash
sudo arp-scan
```

Options:
- `-v, --verbose`: Print detailed progress information
- `-f, --fast`: Use shorter timeouts for quick-responding networks
- `-r, --range <IP>`: Scan custom IP range (e.g., 192.168.0.0/24)
- `-h, --help`: Display help message

Examples:
```bash
# Scan with verbose output
sudo arp-scan -v

# Fast scan with shorter timeouts
sudo arp-scan -f

# Scan specific network range
sudo arp-scan -r 192.168.1.0/24

# Combine options
sudo arp-scan -v -f -r 192.168.0.0/24
```
Note: On Windows, run from an Administrator command prompt without `sudo`.

## Output Format

Default output format:
```IP_ADDRESS MAC_ADDRESS
```

Example:
```
192.168.0.1 40:0D:10:88:92:90
192.168.0.2 00:12:41:89:3F:4C
```

Verbose mode additionally shows:
- Local IP address
- Network interface being used
- Real-time host discovery
- Scan progress information

## Label Lookup

The scanner supports mapping MAC addresses to custom labels using a `labels.txt` file. When enabled with the `-l` or `--lookup` option, the scanner will read MAC address to label mappings and include them in the output.

### Label File Format

Create a file named `labels.txt` in the same directory as the scanner with entries in the following format:
```
MAC_ADDRESS=LABEL
```

Example `labels.txt`:
```
40:0D:10:88:92:90=Router
00:12:41:89:3F:4C=NAS
```

### Output with Labels

When label lookup is enabled, the output format becomes:
```
IP_ADDRESS MAC_ADDRESS LABEL
```
Example:
```
192.168.0.1 40:0D:10:88:92:90 Router
192.168.0.2 00:12:41:89:3F:4C NAS
```

Note: MAC addresses in the labels file are case-insensitive.

## Performance

- Default mode: 2-second scan duration with 10ms packet timeout
- Fast mode: 0.5-second scan duration with 5ms packet timeout

## Notes

- Requires administrator/root privileges due to raw socket operations
- Fast mode may miss slower responding hosts
- Custom range option overrides auto-detected network range

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


