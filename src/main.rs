/// This example demonstrates the essential usage of active filtering modes for packet processing. It selects a
/// network interface and sets it into a filtering mode, where both sent and received packets are queued. The example
/// registers a Win32 event using the `Ndisapi::set_packet_event` function, and enters a waiting state for incoming packets.
/// Upon receiving a packet, its content is decoded and displayed on the console screen, providing a real-time view of
/// the network traffic.
use clap::Parser;
use ndisapi::{
    DirectionFlags,
    EthRequest,
    EthRequestMut,
    FilterFlags,
    IntermediateBuffer,
    Ndisapi,
};
use smoltcp::wire::{
    ArpPacket,
    EthernetFrame,
    EthernetProtocol,
    Icmpv4Packet,
    Icmpv6Packet,
    IpProtocol,
    Ipv4Packet,
    Ipv6Packet,
    TcpPacket,
    UdpPacket,
};
use windows::{
    core::Result,
    Win32::Foundation::{ CloseHandle, HANDLE },
    Win32::System::Threading::{ CreateEventW, ResetEvent, WaitForSingleObject },
};
use tokio::sync::mpsc::{ self, Sender, Receiver };
use std::thread;
use std::mem::transmute;
use tokio::time::{ sleep, Duration };

#[derive(Parser)]
struct Cli {
    #[clap(short, long)]
    interface_index: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Cli { mut interface_index } = Cli::parse();
    interface_index -= 1;

    let driver = Ndisapi::new("NDISRD").expect("WinpkFilter driver yüklenemedi!");
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    println!("Mevcut adaptörler:");
    for (idx, adapter) in adapters.iter().enumerate() {
        println!("Index {}: {}", idx + 1, adapter.get_name());
    }

    if interface_index + 1 > adapters.len() {
        panic!("Geçersiz interface index.");
    }

    let event: HANDLE;
    unsafe {
        event = CreateEventW(None, true, false, None)?;
    }
    driver.set_packet_event(adapters[interface_index].get_handle(), unsafe { transmute(event) })?;
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL
    )?;

    let (tx, rx): (Sender<IntermediateBuffer>, Receiver<IntermediateBuffer>) = mpsc::channel(100);

    // Arka planda paket işleyici thread başlat
    tokio::spawn(async move {
        process_packets(rx).await;
    });

    loop {
        let mut packet = IntermediateBuffer::default();
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }

        loop {
            let mut read_request = EthRequestMut::new(adapters[interface_index].get_handle());
            read_request.set_packet(&mut packet);
            if driver.read_packet(&mut read_request).is_err() {
                break;
            }

            if is_web_packet(&packet) {
                tx.send(packet.clone()).await.ok();
            }
        }

        let _ = unsafe { ResetEvent(event) };

        sleep(Duration::from_millis(50)).await;
    }

    driver.set_adapter_mode(adapters[interface_index].get_handle(), FilterFlags::default())?;
    let _ = unsafe { CloseHandle(event) };
    Ok(())
}

fn is_web_packet(packet: &IntermediateBuffer) -> bool {
    let eth_hdr = EthernetFrame::new_unchecked(packet.get_data());
    match eth_hdr.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new_unchecked(eth_hdr.payload());
            if let IpProtocol::Tcp = ipv4_packet.next_header() {
                let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload());
                let src_port = tcp_packet.src_port();
                let dst_port = tcp_packet.dst_port();
                // Yalnızca HTTP (80) ve HTTPS (443) portlarını kontrol et
                src_port == 80 || src_port == 443 || dst_port == 80 || dst_port == 443
            } else {
                false
            }
        }
        EthernetProtocol::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new_unchecked(eth_hdr.payload());
            if let IpProtocol::Tcp = ipv6_packet.next_header() {
                let tcp_packet = TcpPacket::new_unchecked(ipv6_packet.payload());
                let src_port = tcp_packet.src_port();
                let dst_port = tcp_packet.dst_port();
                src_port == 80 || src_port == 443 || dst_port == 80 || dst_port == 443
            } else {
                false
            }
        }
        _ => false,
    }
}

async fn process_packets(mut rx: Receiver<IntermediateBuffer>) {
    while let Some(packet) = rx.recv().await {
        let length = packet.get_length();
        let flags = packet.get_device_flags();
        println!("Packet Size: {} bytes | Direction: {:?}", length, flags);

        // İşlem arası asenkron bekleme süresi
        sleep(Duration::from_millis(100)).await;
    }
}

async fn print_packet_info(packet: &IntermediateBuffer) {
    let eth_hdr = EthernetFrame::new_unchecked(packet.get_data());
    match eth_hdr.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new_unchecked(eth_hdr.payload());
            println!("  Ipv4 {:?} => {:?}", ipv4_packet.src_addr(), ipv4_packet.dst_addr());
            match ipv4_packet.next_header() {
                IpProtocol::Icmp => {
                    let icmp_packet = Icmpv4Packet::new_unchecked(ipv4_packet.payload());
                    println!(
                        "ICMPv4: Type: {:?} Code: {:?}",
                        icmp_packet.msg_type(),
                        icmp_packet.msg_code()
                    );
                }
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload());
                    println!("   TCP {:?} -> {:?}", tcp_packet.src_port(), tcp_packet.dst_port());
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload());
                    println!("   UDP {:?} -> {:?}", udp_packet.src_port(), udp_packet.dst_port());
                }
                _ => {
                    println!("Unknown IPv4 packet: {:?}", ipv4_packet);
                }
            }
        }
        EthernetProtocol::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new_unchecked(eth_hdr.payload());
            println!("  Ipv6 {:?} => {:?}", ipv6_packet.src_addr(), ipv6_packet.dst_addr());
            match ipv6_packet.next_header() {
                IpProtocol::Icmpv6 => {
                    let icmpv6_packet = Icmpv6Packet::new_unchecked(ipv6_packet.payload());
                    println!(
                        "ICMPv6 packet: Type: {:?} Code: {:?}",
                        icmpv6_packet.msg_type(),
                        icmpv6_packet.msg_code()
                    );
                }
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv6_packet.payload());
                    println!("   TCP {:?} -> {:?}", tcp_packet.src_port(), tcp_packet.dst_port());
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv6_packet.payload());
                    println!("   UDP {:?} -> {:?}", udp_packet.src_port(), udp_packet.dst_port());
                }
                _ => {
                    println!("Unknown IPv6 packet: {:?}", ipv6_packet);
                }
            }
        }
        EthernetProtocol::Arp => {
            let arp_packet = ArpPacket::new_unchecked(eth_hdr.payload());
            println!("ARP packet: {:?}", arp_packet);
        }
        EthernetProtocol::Unknown(_) => {
            println!("Unknown Ethernet packet: {:?}", eth_hdr);
        }
    }
}
