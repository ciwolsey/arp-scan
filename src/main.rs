use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use std::thread;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::env;
use std::fs::File;
use std::io::{self, BufRead};
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
type Labels = HashMap<String, String>;

struct ScanOptions {
    verbose: bool,
    fast_mode: bool,
    custom_range: Option<IpNetwork>,
    lookup_labels: bool,
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
        let path = Path::new("labels.txt");
        
        if !path.exists() {
            return Ok(labels);
        }

        let file = File::open(path)?;
        for line in io::BufReader::new(file).lines() {
            let line = line?;
            if let Some((mac, label)) = line.split_once('=') {
                labels.insert(mac.trim().to_uppercase(), label.trim().to_string());
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
        
        thread::spawn(move || {
            let start = std::time::Instant::now();
            let scan_duration = Duration::from_millis(if fast_mode { 500 } else { 2000 });

            if verbose {
                println!("Started listening for responses...");
            }

            while start.elapsed() < scan_duration {
                if let Ok(packet) = rx.next() {
                    Self::process_packet(&discovered_hosts, packet, verbose);
                }
            }

            let sweep_count = if fast_mode { 5 } else { 10 };
            for _ in 0..sweep_count {
                if let Ok(packet) = rx.next() {
                    Self::process_packet(&discovered_hosts, packet, verbose);
                }
            }
        })
    }

    fn process_packet(discovered_hosts: &DiscoveredHosts, packet: &[u8], verbose: bool) {
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
                        }
                    }
                }
            }
        }
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
        Ok(())
    }

    fn print_results(&self) {
        let hosts = self.discovered_hosts.lock().unwrap();
        let mut hosts: Vec<_> = hosts.iter().collect();
        hosts.sort_by_key(|&(ip, _)| ip.octets());
        
        for (ip, mac) in hosts {
            let mac_str = mac.to_string().to_uppercase();
            if let Some(labels) = &self.labels {
                if let Some(label) = labels.get(&mac_str) {
                    println!("{}\t{}\t{}", ip, mac_str, label);
                    continue;
                }
            }
            // If no label or labels not enabled, print without label
            println!("{}\t{}", ip, mac_str);
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
    println!("  -h, --help        Display this help message\n");
    println!("Output Format:");
    println!("  Default:");
    println!("    192.168.0.1\t40:0D:10:88:92:90");
    println!("  With labels:");
    println!("    192.168.0.1\t40:0D:10:88:92:90\tRouter");
    println!("    192.168.0.2\t00:12:41:89:3F:4C\tNAS\n");
    println!("Examples:");
    println!("  arp-scan                          Perform a basic network scan");
    println!("  arp-scan -v                       Perform a scan with detailed progress information");
    println!("  arp-scan -f                       Perform a faster scan with shorter timeouts");
    println!("  arp-scan -r 192.168.1.0/24       Scan a specific network range");
    println!("  arp-scan -l                       Include labels from labels.txt\n");
    println!("Label File Format (labels.txt):");
    println!("  MAC_ADDRESS=LABEL");
    println!("  Example: 40:0D:10:88:92:90=Router\n");
    println!("Notes:");
    println!("  - Requires administrator/root privileges");
    println!("  - Automatically detects and uses the primary network interface");
    println!("  - MAC addresses are displayed in uppercase");
    println!("  - Fast mode (-f) reduces scan time but may miss slower hosts");
    println!("  - Custom range option overrides auto-detected network range");
    println!("  - Labels file (labels.txt) is optional");
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

    let options = ScanOptions {
        verbose: args.iter().any(|arg| arg == "-v" || arg == "--verbose"),
        fast_mode: args.iter().any(|arg| arg == "-f" || arg == "--fast"),
        custom_range,
        lookup_labels: args.iter().any(|arg| arg == "-l" || arg == "--lookup"),
    };

    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_usage();
        return Ok(());
    }

    let scanner = ArpScanner::new(options)?;
    scanner.scan_network()
}
