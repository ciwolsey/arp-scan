use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use std::thread;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::env;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;
use pnet::datalink::{self, NetworkInterface, Config};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use ipnetwork::IpNetwork;
use local_ip_address::local_ip;
use std::str::FromStr;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type DiscoveredHosts = Arc<Mutex<HashMap<Ipv4Addr, MacAddr>>>;
type Labels = HashMap<String, (String, Option<String>)>;

struct ScanOptions {
    verbose: bool,
    fast_mode: bool,
    custom_range: Option<IpNetwork>,
    lookup_labels: bool,
    update_hosts: bool,
    dummy_mode: bool,
}

struct ArpScanner {
    interface: NetworkInterface,
    local_ip: IpAddr,
    discovered_hosts: DiscoveredHosts,
    options: ScanOptions,
    labels: Option<Labels>,
}

impl ArpScanner {
    fn new(options: ScanOptions) -> Result<Self> {
        let local_ip = local_ip()?;
        if options.verbose {
            println!("Local IP address: {}", local_ip);
            if options.fast_mode {
                println!("Fast mode enabled - using shorter timeouts");
            }
        }

        let interface = Self::find_interface(&local_ip)?;
        if options.verbose {
            println!("Using interface: {}", interface.name);
        }

        let labels = if options.lookup_labels {
            Some(Self::load_labels()?)
        } else {
            None
        };

        Ok(Self {
            interface,
            local_ip,
            discovered_hosts: Arc::new(Mutex::new(HashMap::new())),
            options,
            labels,
        })
    }

    fn load_labels() -> Result<Labels> {
        let mut labels = HashMap::new();
        
        if !Path::new("labels.txt").exists() {
            return Ok(labels);
        }

        let file = File::open("labels.txt")?;
        for line in io::BufReader::new(file).lines() {
            let line = line?;
            let parts: Vec<&str> = line.split('=').collect();
            if parts.len() >= 2 {
                let mac = parts[0].trim().to_uppercase();
                let label = parts[1].trim().to_string();
                let hostname = if parts.len() >= 3 {
                    Some(parts[2].trim().to_string())
                } else {
                    None
                };
                labels.insert(mac, (label, hostname));
            }
        }

        Ok(labels)
    }

    fn find_interface(local_ip: &IpAddr) -> Result<NetworkInterface> {
        datalink::interfaces()
            .into_iter()
            .find(|iface| iface.ips.iter().any(|ip| ip.ip() == *local_ip))
            .ok_or_else(|| "Failed to find network interface".into())
    }

    fn create_channel(&self) -> Result<(Box<dyn datalink::DataLinkSender>, Box<dyn datalink::DataLinkReceiver>)> {
        let config = Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: Some(Duration::from_millis(if self.options.fast_mode { 5 } else { 10 })),
            write_timeout: None,
            channel_type: datalink::ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: true,
        };

        match datalink::channel(&self.interface, config) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
            _ => Err("Failed to create channel".into()),
        }
    }

    fn create_arp_request(&self, target_ip: Ipv4Addr) -> Result<[u8; 42]> {
        let source_mac = self.interface.mac.ok_or("No MAC address found for interface")?;
        let mut buffer = [0u8; 42];
        
        if let IpAddr::V4(source_ip) = self.local_ip {
            let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
            ethernet_packet.set_destination(MacAddr::broadcast());
            ethernet_packet.set_source(source_mac);
            ethernet_packet.set_ethertype(EtherTypes::Arp);

            let mut arp_buffer = [0u8; 28];
            let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Request);
            arp_packet.set_sender_hw_addr(source_mac);
            arp_packet.set_sender_proto_addr(source_ip);
            arp_packet.set_target_hw_addr(MacAddr::zero());
            arp_packet.set_target_proto_addr(target_ip);

            ethernet_packet.set_payload(arp_packet.packet_mut());
            Ok(buffer)
        } else {
            Err("Local IP is not IPv4".into())
        }
    }

    fn start_listener(&self, mut rx: Box<dyn datalink::DataLinkReceiver>) -> thread::JoinHandle<()> {
        let discovered_hosts = Arc::clone(&self.discovered_hosts);
        let verbose = self.options.verbose;
        let fast_mode = self.options.fast_mode;
        let labels = self.labels.clone();
        
        thread::spawn(move || {
            let start = std::time::Instant::now();
            let scan_duration = Duration::from_millis(if fast_mode { 500 } else { 2000 });

            if verbose {
                println!("Started listening for responses...");
            }

            while start.elapsed() < scan_duration {
                if let Ok(packet) = rx.next() {
                    Self::process_packet(&discovered_hosts, packet, verbose, &labels);
                }
            }

            let sweep_count = if fast_mode { 5 } else { 10 };
            for _ in 0..sweep_count {
                if let Ok(packet) = rx.next() {
                    Self::process_packet(&discovered_hosts, packet, verbose, &labels);
                }
            }
        })
    }

    fn process_packet(discovered_hosts: &DiscoveredHosts, packet: &[u8], verbose: bool, labels: &Option<Labels>) {
        if let Some(ethernet) = EthernetPacket::new(packet) {
            if ethernet.get_ethertype() == EtherTypes::Arp {
                if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                    if arp.get_operation() == ArpOperations::Reply {
                        let sender_ip = arp.get_sender_proto_addr();
                        let sender_mac = arp.get_sender_hw_addr();
                        
                        let mut hosts = discovered_hosts.lock().unwrap();
                        if !hosts.contains_key(&sender_ip) {
                            hosts.insert(sender_ip, sender_mac);
                            if verbose {
                                println!("Host {} is up (MAC: {})", sender_ip, sender_mac.to_string().to_uppercase());
                            }
                            // Only ensure host entry if lookup is enabled
                            if labels.is_some() {
                                if let Err(e) = Self::ensure_host_entry(sender_mac) {
                                    eprintln!("Warning: Failed to update labels.txt: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn ensure_host_entry(mac: MacAddr) -> Result<()> {
        let mac_str = mac.to_string().to_uppercase();
        
        // Read existing entries
        let mut entries = Vec::new();
        if Path::new("labels.txt").exists() {
            let file = File::open("labels.txt")?;
            for line in io::BufReader::new(file).lines() {
                entries.push(line?);
            }
        }

        // Check if MAC already exists
        if !entries.iter().any(|line| line.starts_with(&mac_str)) {
            // Add new entry with blank label and hostname
            entries.push(format!("{}==", mac_str));
            
            // Write back all entries
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open("labels.txt")?;
            
            for entry in entries {
                writeln!(file, "{}", entry)?;
            }
        }

        Ok(())
    }

    fn update_hosts_file(&self) -> Result<()> {
        let hosts_path = Path::new(r"C:\Windows\System32\drivers\etc\hosts");
        if !hosts_path.exists() && !self.options.dummy_mode {
            return Err("Windows hosts file not found".into());
        }

        // Read existing hosts file
        let hosts_content = if self.options.dummy_mode {
            String::new()
        } else {
            std::fs::read_to_string(hosts_path)?
        };

        // Prepare new entries and updates
        let mut new_entries = String::new();
        let hosts = self.discovered_hosts.lock().unwrap();
        
        // First, collect all IPs and hostnames from labels.txt that we'll be managing
        let mut managed_ips = std::collections::HashSet::new();
        let mut managed_hostnames = std::collections::HashSet::new();
        
        if let Some(labels) = &self.labels {
            for (mac, (_, hostname)) in labels.iter() {
                if let Some(hostname) = hostname {
                    managed_hostnames.insert(hostname.clone());
                }
                if let Some((ip, _)) = hosts.iter().find(|(_, m)| m.to_string().to_uppercase() == *mac) {
                    managed_ips.insert(*ip);
                }
            }
        }

        // Remove all existing entries that match our managed IPs or hostnames
        let mut lines: Vec<&str> = hosts_content.lines().collect();
        lines.retain(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                // Keep the line if it's not an IP entry
                if parts[0].parse::<Ipv4Addr>().is_err() {
                    true
                } else {
                    // Keep the line if its IP and hostname are not in our managed sets
                    !managed_ips.contains(&parts[0].parse::<Ipv4Addr>().unwrap()) &&
                    !managed_hostnames.contains(parts[1])
                }
            } else {
                true
            }
        });
        let file_content = lines.join("\n");

        // Now prepare new entries
        if let Some(labels) = &self.labels {
            // Create a vector of entries to sort
            let mut entries: Vec<(Ipv4Addr, String)> = Vec::new();
            for (ip, mac) in hosts.iter() {
                let mac_str = mac.to_string().to_uppercase();
                if let Some((_, Some(hostname))) = labels.get(&mac_str) {
                    entries.push((*ip, hostname.clone()));
                }
            }
            // Sort entries by IP address
            entries.sort_by_key(|&(ip, _)| ip.octets());
            
            // Calculate the maximum IP width from both existing and new entries
            let max_ip_width = file_content.lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 && parts[0].parse::<Ipv4Addr>().is_ok() {
                        Some(parts[0].len())
                    } else {
                        None
                    }
                })
                .chain(entries.iter().map(|(ip, _)| ip.to_string().len()))
                .max()
                .unwrap_or(15);
            
            // Create the new entries string from sorted entries
            for (ip, hostname) in entries {
                new_entries.push_str(&format!("{:<width$}\t\t{}\n", ip, hostname, width = max_ip_width));
            }

            if !new_entries.is_empty() {
                if self.options.dummy_mode {
                    println!("\nEntries to be added:");
                    println!("----------------------------------------");
                    print!("{}", new_entries);
                    println!("----------------------------------------");
                } else {
                    // Write back the file with updates
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(hosts_path)?;
                    
                    // Normalize existing entries to use two tabs and align IPs
                    let normalized_content = file_content.lines()
                        .map(|line| {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 2 && parts[0].parse::<Ipv4Addr>().is_ok() {
                                format!("{:<width$}\t\t{}", parts[0], parts[1], width = max_ip_width)
                            } else {
                                line.to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n");

                    std::io::Write::write_all(&mut file, normalized_content.as_bytes())?;
                    if !normalized_content.ends_with('\n') {
                        std::io::Write::write_all(&mut file, b"\n")?;
                    }
                    std::io::Write::write_all(&mut file, new_entries.as_bytes())?;
                    
                    if self.options.verbose {
                        let new_count = new_entries.lines().count();
                        println!("Updated hosts file with {} entries", new_count);
                    }
                }
            } else if self.options.dummy_mode {
                println!("\nNo changes would be made to hosts file.");
            }
        }

        Ok(())
    }

    fn scan_network(&self) -> Result<()> {
        let (mut tx, rx) = self.create_channel()?;
        let listening_thread = self.start_listener(rx);

        if let IpAddr::V4(local_ip) = self.local_ip {
            // Add local machine to discovered hosts
            if let Some(local_mac) = self.interface.mac {
                let mut hosts = self.discovered_hosts.lock().unwrap();
                hosts.insert(local_ip, local_mac);
                if self.options.verbose {
                    println!("Local machine: {} (MAC: {})", local_ip, local_mac.to_string().to_uppercase());
                }
            }

            let network = if let Some(custom_range) = &self.options.custom_range {
                if self.options.verbose {
                    println!("Using custom network range: {}", custom_range);
                }
                custom_range.clone()
            } else {
                if let Some(network) = self.interface
                    .ips
                    .iter()
                    .find(|ip| ip.ip() == self.local_ip)
                {
                    if self.options.verbose {
                        println!("Auto-detected network: {}", network);
                    }
                    network.clone()
                } else {
                    return Err("Failed to find network".into());
                }
            };

            if let IpNetwork::V4(network) = network {
                if self.options.verbose {
                    println!("Sending ARP requests...");
                }

                let mut packets: Vec<_> = network.iter()
                    .map(|ip| self.create_arp_request(ip))
                    .collect::<Result<Vec<_>>>()?;

                for chunk in packets.chunks_mut(32) {
                    for packet in chunk {
                        tx.send_to(packet, None);
                    }
                    thread::sleep(Duration::from_micros(100));
                }
            } else {
                return Err("Only IPv4 networks are supported".into());
            }
        }

        listening_thread.join().unwrap();
        self.print_results();
        
        if self.options.update_hosts {
            self.update_hosts_file()?;
        }
        
        Ok(())
    }

    fn print_results(&self) {
        let hosts = self.discovered_hosts.lock().unwrap();
        let mut hosts: Vec<_> = hosts.iter().collect();
        hosts.sort_by_key(|&(ip, _)| ip.octets());
        
        // Calculate maximum widths for each column
        let mut max_ip_width = 15;  // Minimum width for IP
        let mut max_mac_width = 17;  // Minimum width for MAC
        let mut max_label_width = 0;
        let mut max_hostname_width = 0;

        // First pass: calculate maximum widths
        for (ip, mac) in &hosts {
            let mac_str = mac.to_string().to_uppercase();
            max_ip_width = max_ip_width.max(ip.to_string().len());
            max_mac_width = max_mac_width.max(mac_str.len());
            
            if let Some(labels) = &self.labels {
                if let Some((label, hostname)) = labels.get(&mac_str) {
                    max_label_width = max_label_width.max(label.len());
                    if let Some(hostname) = hostname {
                        max_hostname_width = max_hostname_width.max(hostname.len());
                    }
                }
            }
        }

        // Print data rows with proper alignment
        for (ip, mac) in hosts {
            let mac_str = mac.to_string().to_uppercase();
            if let Some(labels) = &self.labels {
                if let Some((label, hostname)) = labels.get(&mac_str) {
                    match hostname {
                        Some(hostname) => println!("{:<ip_width$}\t{:<mac_width$}\t{:<hostname_width$}\t{:<label_width$}",
                            ip, mac_str, hostname, label,
                            ip_width = max_ip_width,
                            mac_width = max_mac_width,
                            hostname_width = max_hostname_width,
                            label_width = max_label_width),
                        None => println!("{:<ip_width$}\t{:<mac_width$}\t{:<label_width$}",
                            ip, mac_str, label,
                            ip_width = max_ip_width,
                            mac_width = max_mac_width,
                            label_width = max_label_width),
                    }
                    continue;
                }
            }
            // If no label or labels not enabled, print without label
            println!("{:<ip_width$}\t{:<mac_width$}",
                ip, mac_str,
                ip_width = max_ip_width,
                mac_width = max_mac_width);
        }
    }
}

fn print_usage() {
    println!("arp-scan - Fast ARP network scanner\n");
    println!("Usage:");
    println!("  arp-scan [OPTIONS]\n");
    println!("Description:");
    println!("  Scans the local network using ARP requests to discover active hosts.\n");
    println!("Options:");
    println!("  -v, --verbose     Print detailed progress information");
    println!("  -f, --fast        Use shorter timeouts for quick-responding networks");
    println!("  -r, --range <IP>  Scan custom IP range (e.g., 192.168.0.0/24)");
    println!("  -l, --lookup      Look up labels from labels.txt file");
    println!("  --add-hosts       Update Windows hosts file with discovered hostnames");
    println!("  --dummy          Preview hosts file updates without making changes");
    println!("  -h, --help        Display this help message\n");
    println!("Output Format:");
    println!("  Default:");
    println!("    192.168.0.1\t40:0D:10:88:92:90");
    println!("  With labels:");
    println!("    192.168.0.1\t40:0D:10:88:92:90\tRouter\trouter.local");
    println!("    192.168.0.2\t00:12:41:89:3F:4C\tNAS\tnas.local\n");
    println!("Examples:");
    println!("  arp-scan                          Perform a basic network scan");
    println!("  arp-scan -v                       Perform a scan with detailed progress information");
    println!("  arp-scan -f                       Perform a faster scan with shorter timeouts");
    println!("  arp-scan -r 192.168.1.0/24       Scan a specific network range");
    println!("  arp-scan -l                       Include labels from labels.txt");
    println!("  arp-scan -l --add-hosts          Update hosts file with discovered hostnames");
    println!("  arp-scan -l --add-hosts --dummy  Preview hosts file updates\n");
    println!("Label File Format (labels.txt):");
    println!("  MAC_ADDRESS=LABEL=HOSTNAME");
    println!("  Example: 40:0D:10:88:92:90=Router=router.local");
    println!("  Note: HOSTNAME is optional\n");
    println!("Notes:");
    println!("  - Requires administrator/root privileges");
    println!("  - Automatically detects and uses the primary network interface");
    println!("  - MAC addresses are displayed in uppercase");
    println!("  - Fast mode (-f) reduces scan time but may miss slower hosts");
    println!("  - Custom range option overrides auto-detected network range");
    println!("  - Labels file (labels.txt) is optional");
    println!("  - --add-hosts option requires --lookup and hostnames in labels.txt");
    println!("  - --dummy option can be used with --add-hosts to preview changes");
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    // Parse custom range if provided
    let custom_range = args.iter()
        .position(|arg| arg == "-r" || arg == "--range")
        .and_then(|i| args.get(i + 1))
        .map(|range| IpNetwork::from_str(range))
        .transpose()
        .map_err(|e| format!("Invalid IP range: {}", e))?;

    let update_hosts = args.iter().any(|arg| arg == "--add-hosts");
    let lookup_labels = args.iter().any(|arg| arg == "-l" || arg == "--lookup");
    let dummy_mode = args.iter().any(|arg| arg == "--dummy");

    // Validate that --add-hosts requires --lookup
    if update_hosts && !lookup_labels {
        eprintln!("Error: --add-hosts option requires --lookup");
        return Err("Invalid options".into());
    }

    let options = ScanOptions {
        verbose: args.iter().any(|arg| arg == "-v" || arg == "--verbose"),
        fast_mode: args.iter().any(|arg| arg == "-f" || arg == "--fast"),
        custom_range,
        lookup_labels,
        update_hosts,
        dummy_mode,
    };

    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_usage();
        return Ok(());
    }

    let scanner = ArpScanner::new(options)?;
    scanner.scan_network()
}
