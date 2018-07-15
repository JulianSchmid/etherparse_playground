use std::io::BufReader;
use std::fs::File;
use std::env;

extern crate rpcap;
use self::rpcap::read::PcapReader;

extern crate etherparse;
use self::etherparse::*;

extern crate time;
use time::PreciseTime;

fn get_size(file: &String) -> (usize, usize) {
    
    let mut pcapr = PcapReader::new(BufReader::new(File::open(file).unwrap())).unwrap();
    let mut count = 0;
    let mut memsize = 0;
    while let Some(packet) = pcapr.next().unwrap() {
        count += 1;
        memsize += packet.data.len();
    }
    (count, memsize)
}

fn read(packets: &Vec<Vec<u8>>) {
    let start = PreciseTime::now();
    
    let mut ok = 0;
    let mut err = 0;
    let mut eth_payload = 0;
    let mut ipv4 = 0;
    let mut ipv6 = 0;
    let mut ip_payload = 0;
    let mut udp = 0;
    for packet in packets {
        let decoded = PacketHeaders::from_ethernet_slice(&packet);
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

fn main() {
        let file = env::args().nth(1).unwrap();

    let (count, _) = get_size(&file);

    //copy to memory
    let mut packets = Vec::with_capacity(count);
    {
        let mut pcapr = PcapReader::new(BufReader::new(File::open(&file).unwrap())).unwrap();
        while let Some(packet) = pcapr.next().unwrap() {
            packets.push({
                let mut buffer = Vec::with_capacity(packet.data.len());
                buffer.extend_from_slice(packet.data);
                buffer
            });
        }
    }

    println!("done copying to memory");
    read(&packets);
    read(&packets);
    read(&packets);
    read(&packets);
    read(&packets);
}