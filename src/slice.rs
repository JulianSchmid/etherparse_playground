use std::io::BufReader;
use std::fs::{File, Metadata};
use std::env;
extern crate rpcap;
use self::rpcap::read::PcapReader;

extern crate etherparse;
use self::etherparse::*;

extern crate time;
use time::PreciseTime;

extern crate glob;
use glob::glob;

extern crate csv;
use csv::Writer;

#[macro_use]
extern crate serde_derive;


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

#[derive(Serialize)]
struct ResultStats<'a> {
    path: &'a str,
    duration_secs: f64,
    file_size: u64,
    total_packets_size: usize,
    gigabytes_per_sec_file: f64,
    gigabytes_per_sec_packets: f64
}

#[derive(Debug)]
enum Error {
    IoError(std::io::Error),
    PcapError(rpcap::PcapError),

}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<rpcap::PcapError> for Error {
    fn from(err: rpcap::PcapError) -> Error {
        Error::PcapError(err)
    }
}

use TcpOptionElement::*;

fn read(in_file_path: &str, in_file_metadata: Metadata, result_writer: &mut Writer<File>) -> Result<(),Error> {
    let start = PreciseTime::now();

    let mut reader = PcapReader::new(BufReader::new(File::open(&in_file_path)?))?;

    let mut stats: Stats = Default::default();

    while let Some(packet) = reader.next()? {
        stats.total_payload_size += packet.data.len();

        let sliced = SlicedPacket::from_ethernet(&packet.data);

        match sliced {
            Err(_) => {
                stats.err += 1;
            },
            Ok(value) => {
                stats.ok += 1;
                use InternetSlice::*;
                use TransportSlice::*;

                match &value.ip {
                    Some(Ipv4(_)) => {
                        stats.ipv4 += 1;
                    },
                    Some(Ipv6(_,_)) => {
                        stats.ipv6 += 1;
                    },
                    None => {
                        stats.eth_payload += 1;
                    }
                }

                match value.transport {
                    Some(Udp(_)) => {
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
                        if value.ip.is_some() {
                            stats.ip_payload += 1;
                        }
                    }
                }
            }
        }
    }

    let duration = start.to(PreciseTime::now()).to_std().unwrap();
    let duration_secs = duration.as_secs() as f64 + duration.subsec_nanos() as f64 * 1e-9;
    //let gigabits_per_sec = in_file_metadata.len() as f64 / duration_secs / 125_000_000.0;
    let gigabytes_per_sec_file = in_file_metadata.len() as f64 / duration_secs /  1_000_000_000.0;
    //let gigabits_per_sec_payload = stats.total_payload_size as f64 / duration_secs / 125_000_000.0;
    let gigabytes_per_sec_packets = stats.total_payload_size as f64 / duration_secs / 1_000_000_000.0;

    println!("{}", in_file_path);
    println!("{:?}", stats);
    println!("{:?}", duration);
    println!("{:?}GB/s (file)", gigabytes_per_sec_file);
    println!("{:?}GB/s (packets data)", gigabytes_per_sec_packets);

    result_writer.serialize(ResultStats {
        path: in_file_path,
        duration_secs: duration_secs,
        file_size: in_file_metadata.len(),
        total_packets_size: stats.total_payload_size,
        gigabytes_per_sec_file: gigabytes_per_sec_file,
        gigabytes_per_sec_packets: gigabytes_per_sec_packets
    }).unwrap();
    
    Ok(())
    //writeln!(result_writer, "{},{},{},{},{}", duration_secs, in_file_metadata.len(), stats.total_payload_size, gigabytes_per_sec, gigabytes_per_sec_payload).unwrap();
}

fn main() {
    let in_file_path = env::args().nth(1).unwrap();
    let mut out_file = Writer::from_path(&env::args().nth(2).unwrap()).unwrap();

    for entry in glob(&in_file_path).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                let path_str = path.to_str().unwrap();
                let in_file_metadata = std::fs::metadata(&path_str).unwrap();
                //let mut pcapr = PcapReader::new(BufReader::new(File::open(&in_file_path).unwrap())).unwrap();
                match read(&path_str, in_file_metadata, &mut out_file) {
                    Ok(_) => {},
                    Err(err) => println!("{:?}", err)
                }
            },
            Err(e) => println!("{:?}", e),
        }
    }

    /*
    for _i in 0..100 {
        let in_file_metadata = std::fs::metadata(&in_file_path).unwrap();
        //let mut pcapr = PcapReader::new(BufReader::new(File::open(&in_file_path).unwrap())).unwrap();
        read(&in_file_path, in_file_metadata, &mut out_file);
    }*/
}