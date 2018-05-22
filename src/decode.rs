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
        let decoded = PacketHeaders::decode(&packet.data);
        use IpHeader::*;
        match decoded {
            Ok(value) => {
                ok += 1;
                match value.ip {
                    Some(Version4(_value)) => {
                        ipv4 += 1;
                    },
                    Some(Version6(_value)) => {
                        ipv6 += 1;
                    },
                    None => {
                        eth_payload += 1;
                    }
                }
                match value.transport {
                    Some(_value) => {
                        udp += 1;
                    },
                    None => {
                        ip_payload += 1;
                    }
                }
            },
            Err(_) => {
                err += 1
            }
        }
    }

    println!("ok={:?}, err={:?}, eth_payload={:?}, ipv4={:?}, ipv6={:?}, ip_payload={:?}, udp={:?}", ok, err, eth_payload, ipv4, ipv6, ip_payload, udp);
    println!("done reading in {:?}", start.to(PreciseTime::now()));
}