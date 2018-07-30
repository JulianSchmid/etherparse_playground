use std::io::{Write,BufReader};
use std::fs::{File, Metadata};
use std::env;

extern crate rpcap;
use self::rpcap::read::PcapReader;

extern crate etherparse;
use self::etherparse::*;

extern crate time;
use time::PreciseTime;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct Stats {
    total_payload_size: usize,
    ok: usize,
    err: usize,
    eth_payload: usize,
    ipv4: usize,
    ipv6: usize,
    ip_payload: usize,
    udp: usize,
    tcp: usize,
    tcp_options_err: usize,
    tcp_options_nop: usize,
    tcp_options_max_seg: usize,
    tcp_options_window_scale: usize,
    tcp_options_selec_ack_perm: usize,
    tcp_options_selec_ack: usize,
    tcp_options_timestamp: usize
}

use TcpOptionElement::*;

fn read(in_file_path: &str, in_file_metadata: Metadata, result_writer: &mut Write) {
    let start = PreciseTime::now();

    let mut reader = PcapReader::new(BufReader::new(File::open(&in_file_path).unwrap())).unwrap();
    
    let mut stats: Stats = Default::default();

    while let Some(packet) = reader.next().unwrap() {
        
        stats.total_payload_size += packet.data.len();

        let decoded = PacketHeaders::from_ethernet_slice(&packet.data);
        use IpHeader::*;
        use TransportHeader::*;
        match decoded {
            Ok(value) => {
                stats.ok += 1;
                match value.ip {
                    Some(Version4(_value)) => {
                        stats.ipv4 += 1;
                    },
                    Some(Version6(_value)) => {
                        stats.ipv6 += 1;
                    },
                    None => {
                        stats.eth_payload += 1;
                    }
                }
                match value.transport {
                    Some(Udp(_value)) => {
                        stats.udp += 1;
                    },
                    Some(Tcp(tcp)) => {
                        stats.tcp += 1;
                        for option in tcp.options_iterator() {
                            match option {
                                Err(_) => stats.tcp_options_err += 1,
                                Ok(Nop) => stats.tcp_options_nop += 1,
                                Ok(MaximumSegmentSize(_)) => stats.tcp_options_max_seg += 1,
                                Ok(WindowScale(_)) => stats.tcp_options_window_scale += 1,
                                Ok(SelectiveAcknowledgementPermitted) => stats.tcp_options_selec_ack_perm += 1,
                                Ok(SelectiveAcknowledgement(_,_)) => stats.tcp_options_selec_ack += 1,
                                Ok(Timestamp(_, _)) => stats.tcp_options_timestamp += 1
                            }
                        }
                    },
                    None => {
                        stats.ip_payload += 1;
                    }
                }
            },
            Err(_) => {
                stats.err += 1
            }
        }
    }

    let duration = start.to(PreciseTime::now()).to_std().unwrap();
    let duration_secs = duration.as_secs() as f64 + duration.subsec_nanos() as f64 * 1e-9;
    //let gigabits_per_sec = in_file_metadata.len() as f64 / duration_secs / 125_000_000.0;
    let gigabytes_per_sec = in_file_metadata.len() as f64 / duration_secs /  1_000_000_000.0;
    //let gigabits_per_sec_payload = stats.total_payload_size as f64 / duration_secs / 125_000_000.0;
    let gigabytes_per_sec_payload = stats.total_payload_size as f64 / duration_secs / 1_000_000_000.0;

    println!("{:?}", stats);
    println!("{:?}", duration);
    println!("{:?}GB/s (file)", gigabytes_per_sec);
    println!("{:?}GB/s (payload)", gigabytes_per_sec_payload);
    
    writeln!(result_writer, "{},{},{},{},{}", duration_secs, in_file_metadata.len(), stats.total_payload_size, gigabytes_per_sec, gigabytes_per_sec_payload).unwrap();
}

fn main() {
    let in_file_path = env::args().nth(1).unwrap();
    let mut out_file = File::create(&env::args().nth(2).unwrap()).unwrap();

    for _i in 0..100 {
        let in_file_metadata = std::fs::metadata(&in_file_path).unwrap();
        //let mut pcapr = PcapReader::new(BufReader::new(File::open(&in_file_path).unwrap())).unwrap();
        read(&in_file_path, in_file_metadata, &mut out_file);
    }
}