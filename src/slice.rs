use std::io::BufReader;
use std::fs::File;
extern crate rpcap;
use self::rpcap::read::PcapReader;

extern crate etherparse;
use self::etherparse::*;

extern crate time;
use time::PreciseTime;

fn main() {
    // read a PCAP file
    let start = PreciseTime::now();
    let mut pcapr = PcapReader::new(BufReader::new(File::open("lulu.pcap").unwrap())).unwrap();
    println!("linktype: {}", pcapr.get_linktype());
    println!("snaplen: {}", pcapr.get_snaplen());

    let mut ok = 0;
    let mut err = 0;
    let mut eth_payload = 0;
    let mut ipv4 = 0;
    let mut ipv6 = 0;
    let mut ip_payload = 0;
    let mut udp = 0;
    while let Some(packet) = pcapr.next().unwrap() {
        for element in PacketSlicer::ethernet2(&packet.data) {
            use PacketSliceType::*;
            match element {
                Ok(value) => {
                    ok += 1;
                    match value {
                        Ethernet2Header(_slice) => {},
                        SingleVlanHeader(_slice) => {},
                        DoubleVlanHeader(_slice) => {},
                        Ethernet2Payload(_ether_type, _payload) => {
                            eth_payload += 1;
                        },
                        Ipv4Header(_slice) => {
                            ipv4 += 1;
                        },
                        Ipv6Header(_slice) => {
                            ipv6 += 1;
                        },
                        Ipv6ExtensionHeader(_header_type, _slice) => {},
                        IpPayload(_protocol, _payload) => {
                            ip_payload += 1;
                        },
                        UdpHeader(_slice) => {
                            udp += 1;
                        },
                        UdpPayload(_payload) => {}
                    }
                },
                Err(_value) => {
                    err += 1;
                }
            }
        }
    }

    println!("ok={:?}, err={:?}, eth_payload={:?}, ipv4={:?}, ipv6={:?}, ip_payload={:?}, udp={:?}", ok, err, eth_payload, ipv4, ipv6, ip_payload, udp);
    println!("done reading in {:?}", start.to(PreciseTime::now()));

}