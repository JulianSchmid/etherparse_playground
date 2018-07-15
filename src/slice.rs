use std::io::BufReader;
use std::fs::File;
use std::env;
extern crate rpcap;
use self::rpcap::read::PcapReader;

extern crate etherparse;
use self::etherparse::*;

extern crate time;
use time::PreciseTime;
use std::time::Duration;


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

fn read<'a>(packets: &Vec<&'a [u8]>) {
    let start = PreciseTime::now();

    let mut ok = 0;
    let mut err = 0;
    let mut eth_payload = 0;
    let mut ipv4 = 0;
    let mut ipv6 = 0;
    let mut ip_payload = 0;
    let mut udp = 0;
    for packet in packets {


        let sliced = SlicedPacket::from_ethernet(&packet);

        match sliced {
            Err(_) => {
                err += 1;
            },
            Ok(value) => {
                ok += 1;
                use InternetSlice::*;
                use TransportSlice::*;

                match value.ip {
                    Some(Ipv4(_)) => {
                        ipv4 += 1;
                    },
                    Some(Ipv6(_,_)) => {
                        ipv6 += 1;
                    },
                    None => {
                        eth_payload += 1;
                    }
                }

                match value.transport {
                    Some(Udp(_)) => {
                        udp += 1;
                    },
                    None => {
                        if value.ip.is_some() {
                            ip_payload += 1;
                        }
                    }
                }
            }
        }

        /*
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
        }*/
    }

    println!("ok={:?}, err={:?}, eth_payload={:?}, ipv4={:?}, ipv6={:?}, ip_payload={:?}, udp={:?}", ok, err, eth_payload, ipv4, ipv6, ip_payload, udp);
    println!("done reading in {:?}", start.to(PreciseTime::now()));
}

fn main() {

    let file = env::args().nth(1).unwrap();

    let (count, memsize) = get_size(&file);

    //copy to memory
    let mut buffer = Vec::with_capacity(memsize);
    {
        let mut pcapr = PcapReader::new(BufReader::new(File::open(&file).unwrap())).unwrap();
        while let Some(packet) = pcapr.next().unwrap() {
            buffer.extend_from_slice(packet.data);
        }
    }

    let mut packets = Vec::with_capacity(count);
    {
        let mut start = 0;
        let mut pcapr = PcapReader::new(BufReader::new(File::open(&file).unwrap())).unwrap();
        while let Some(packet) = pcapr.next().unwrap() {
            packets.push({
                let result = &buffer[start..start + packet.data.len()];
                start += packet.data.len();
                result
            });
        }
    }

    println!("done copying to memory");

    std::thread::sleep(Duration::from_secs(1));

    println!("stoped waiting");

    read(&packets);
}