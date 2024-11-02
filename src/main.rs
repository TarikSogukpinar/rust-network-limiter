use clap::Parser;
use ndisapi::{EthRequest, EthRequestMut, FilterFlags, IntermediateBuffer, Ndisapi};
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket,
};
use std::sync::Arc;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration, Instant};
use windows::{
    Win32::Foundation::{CloseHandle, HANDLE},
    Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject},
};

#[derive(Parser)]
struct Cli {
    #[clap(short, long)]
    interface_index: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Cli {
        mut interface_index,
    } = Cli::parse();
    interface_index -= 1;

    let driver = Ndisapi::new("NDISRD").expect("WinpkFilter driver could not be loaded!");
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    println!("Available adapters:");
    for (idx, adapter) in adapters.iter().enumerate() {
        println!("Index {}: {}", idx + 1, adapter.get_name());
    }

    if interface_index + 1 > adapters.len() {
        panic!("Invalid interface index.");
    }

    let adapter_handle = adapters[interface_index].get_handle();

    let event: HANDLE = unsafe { CreateEventW(None, true, false, None)? };

    driver.set_packet_event(adapter_handle, event)?;

    driver.set_adapter_mode(adapter_handle, FilterFlags::MSTCP_FLAG_SENT_TUNNEL)?;

    let (tx, rx): (Sender<IntermediateBuffer>, Receiver<IntermediateBuffer>) = mpsc::channel(100);

    let upload_limiter = Arc::new(Mutex::new(TokenBucket::new(100_000))); // 1 Mbps limit

    let driver_clone = driver.clone();
    let adapter_handle_clone = adapter_handle;
    let upload_limiter_clone = upload_limiter.clone();

    tokio::spawn(async move {
        process_packets(rx, driver_clone, adapter_handle_clone, upload_limiter_clone).await;
    });

    loop {
        let mut packet = IntermediateBuffer::default();
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }

        loop {
            let mut read_request = EthRequestMut::new(adapter_handle);
            read_request.set_packet(&mut packet);
            if driver.read_packet(&mut read_request).is_err() {
                break;
            }

            tx.send(packet.clone()).await.ok();
        }

        let _ = unsafe { ResetEvent(event) };

        sleep(Duration::from_millis(50)).await;
    }

    driver.set_adapter_mode(adapter_handle, FilterFlags::default())?;
    let _ = unsafe { CloseHandle(event) };
    Ok(())
}

async fn process_packets(
    mut rx: Receiver<IntermediateBuffer>,
    driver: Ndisapi,
    adapter_handle: HANDLE,
    upload_limiter: Arc<Mutex<TokenBucket>>,
) {
    while let Some(packet) = rx.recv().await {
        let length = packet.get_length() as usize;

        // Print packet information for debugging
        print_packet_info(&packet).await;

        // Upload limit check
        {
            let mut limiter = upload_limiter.lock().await;
            if !limiter.consume(length).await {
                // If limit exceeded, drop the packet
                println!("Upload limit reached, dropping packet");
                continue; // Don't send the packet, effectively dropping it
            }
        }

        // Send the packet back to the adapter
        let mut packet_request = EthRequest::new(adapter_handle);
        packet_request.set_packet(&packet);
        driver
            .send_packet_to_adapter(&packet_request)
            .expect("Failed to send packet to adapter");
    }
}

// Add this function to print packet information
async fn print_packet_info(packet: &IntermediateBuffer) {
    let eth_frame = EthernetFrame::new_unchecked(packet.get_data());
    match eth_frame.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new_unchecked(eth_frame.payload());
            println!(
                "IPv4 Packet: {} -> {}",
                ipv4_packet.src_addr(),
                ipv4_packet.dst_addr()
            );
            match ipv4_packet.next_header() {
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload());
                    println!(
                        "TCP Segment: {} -> {}",
                        tcp_packet.src_port(),
                        tcp_packet.dst_port()
                    );
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload());
                    println!(
                        "UDP Datagram: {} -> {}",
                        udp_packet.src_port(),
                        udp_packet.dst_port()
                    );
                }
                _ => {
                    println!("Other IPv4 Protocol: {:?}", ipv4_packet.next_header());
                }
            }
        }
        EthernetProtocol::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new_unchecked(eth_frame.payload());
            println!(
                "IPv6 Packet: {} -> {}",
                ipv6_packet.src_addr(),
                ipv6_packet.dst_addr()
            );
            match ipv6_packet.next_header() {
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv6_packet.payload());
                    println!(
                        "TCP Segment: {} -> {}",
                        tcp_packet.src_port(),
                        tcp_packet.dst_port()
                    );
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv6_packet.payload());
                    println!(
                        "UDP Datagram: {} -> {}",
                        udp_packet.src_port(),
                        udp_packet.dst_port()
                    );
                }
                _ => {
                    println!("Other IPv6 Protocol: {:?}", ipv6_packet.next_header());
                }
            }
        }
        EthernetProtocol::Arp => {
            println!("ARP Packet");
        }
        _ => {
            println!("Other Ethernet Protocol: {:?}", eth_frame.ethertype());
        }
    }
}

struct TokenBucket {
    capacity: usize,
    tokens: usize,
    last_refill: Instant,
    rate: usize, // bytes per second
}

impl TokenBucket {
    fn new(rate: usize) -> Self {
        TokenBucket {
            capacity: rate,
            tokens: rate,
            last_refill: Instant::now(),
            rate,
        }
    }

    async fn consume(&mut self, amount: usize) -> bool {
        self.refill();

        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            // Not enough tokens, wait
            let wait_time =
                Duration::from_secs_f64((amount - self.tokens) as f64 / self.rate as f64);
            sleep(wait_time).await;
            self.refill();
            if self.tokens >= amount {
                self.tokens -= amount;
                true
            } else {
                false
            }
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let new_tokens = (elapsed.as_secs_f64() * self.rate as f64) as usize;

        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = now;
        }
    }
}
