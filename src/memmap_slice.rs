use std::fs::File;
extern crate etherparse_playground;
use self::etherparse_playground::*;
extern crate rpcap;
extern crate etherparse;
use self::etherparse::*;
extern crate glob;
extern crate csv;
#[macro_use]
extern crate clap;
use clap::{Arg, App};

fn read(in_file_path: &str, result_writer: &mut csv::Writer<File>) -> Result<(),Error> {

    let file = File::open(&in_file_path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len();
    /*
    Ok(if !metadata.is_file() {
        // Not a real file.
        None
    } else if file_size > isize::max_value() as u64 {
        // Too long to safely map.
        // https://github.com/danburkert/memmap-rs/issues/69
        None
    } else if file_size == 0 {
        // Mapping an empty file currently fails.
        // https://github.com/danburkert/memmap-rs/issues/72
        None
    } else if file_size < 16 * 1024 {
        // Mapping small files is not worth it.
        None
    } else {*/
    
    let map = unsafe {
        memmap::MmapOptions::new()
            .len(file_size as usize)
            .map(&file)?
    };

    let mut recorder = StatsRecorder::new(in_file_path);
    {
        let stats = &mut recorder.stats;
        //let mut reader = rpcap::read::PcapReader::new(BufReader::new(file))?;
        
        let iter = pcap_parser::LegacyPcapSlice::from_slice(&map).unwrap();

        //while let Some(packet) = reader.next()? {
        for block in iter {
            use pcap_parser::PcapBlockOwned::*;
            match block.as_ref().unwrap() {
                Legacy(ref packet) => {
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
                                Some(Ipv4(_, _)) => {
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

                                        use TcpOptionElement::*;
                                        match option {
                                            Err(_) => stats.tcp_options_err += 1,
                                            Ok(Noop) => stats.tcp_options_noop += 1,
                                            Ok(MaximumSegmentSize(_)) => stats.tcp_options_max_seg += 1,
                                            Ok(WindowScale(_)) => stats.tcp_options_window_scale += 1,
                                            Ok(SelectiveAcknowledgementPermitted) => stats.tcp_options_selec_ack_perm += 1,
                                            Ok(SelectiveAcknowledgement(_,_)) => stats.tcp_options_selec_ack += 1,
                                            Ok(Timestamp(_, _)) => stats.tcp_options_timestamp += 1
                                        }
                                    }
                                },
                                Some(Icmpv4(_)) => {
                                    stats.icmpv4 += 1;
                                },
                                Some(Icmpv6(_)) => {
                                    stats.icmpv6 += 1;
                                },
                                Some(Unknown(_)) => {
                                    stats.transport_unknown += 1;
                                },
                                None => {
                                    if value.ip.is_some() {
                                        stats.ip_payload += 1;
                                    }
                                }
                            }
                        }
                    }
                },
                _ => {}
            }
        }
    }
    result_writer.serialize(recorder.end()).unwrap();
    Ok(())
}

fn main() {

    let matches = App::new("slices all packages of a or multiple pcap(s) to measure performance")
                      .author("Julian Schmid")
                          .arg(Arg::with_name("INPUT")
                               .help("input pcap file or files (can be a glob expression)")
                               .required(true)
                               .index(1))
                          .arg(Arg::with_name("number_of_reads")
                            .takes_value(true)
                            .help("the number of times each file is read")
                            .short("n")
                            .long("number_of_reads"))
                          .arg(Arg::with_name("csv")
                            .takes_value(true)
                            .required(true)
                            .short("c")
                            .long("csv"))
                      .get_matches();

    let number_of_reads = value_t_or_exit!(matches, "number_of_reads", usize);

    let mut out_file = csv::Writer::from_path(&matches.value_of("csv").unwrap()).unwrap();

    for entry in glob::glob(&matches.value_of("INPUT").unwrap()).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                let path_str = path.to_str().unwrap();
                for _i in 0..number_of_reads {
                    match read(&path_str, &mut out_file) {
                        Ok(_) => {},
                        Err(err) => println!("{:?}", err)
                    }
                }
            },
            Err(e) => println!("{:?}", e),
        }
    }
}