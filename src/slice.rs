use std::io::BufReader;
use std::fs::File;
use std::env;
extern crate rpcap;
use self::rpcap::read::PcapReader;

extern crate etherparse;
use self::etherparse::*;

use std::io::Read;

extern crate time;
use time::PreciseTime;

fn read<T: Read>(reader: &mut PcapReader<T>) {
    let start = PreciseTime::now();

    let mut ok = 0;
    let mut err = 0;
    let mut eth_payload = 0;
    let mut ipv4 = 0;
    let mut ipv6 = 0;
    let mut ip_payload = 0;
    let mut udp = 0;
    while let Some(packet) = reader.next().unwrap() {
        let sliced = SlicedPacket::from_ethernet(&packet.data);

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
    }

    println!("ok={:?}, err={:?}, eth_payload={:?}, ipv4={:?}, ipv6={:?}, ip_payload={:?}, udp={:?}", ok, err, eth_payload, ipv4, ipv6, ip_payload, udp);
    println!("done reading in {:?}", start.to(PreciseTime::now()));
}

fn main() {

    let file = env::args().nth(1).unwrap();
    for _i in 0..10 {
        let mut pcapr = PcapReader::new(BufReader::new(File::open(&file).unwrap())).unwrap();
        read(&mut pcapr);
    }
}