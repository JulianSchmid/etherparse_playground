use std::{fs::File, path::PathBuf};
use etherparse_playground::*;
use etherparse::*;
use clap::Parser;

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
                            use NetSlice::*;
                            use TransportSlice::*;

                            match &value.net {
                                Some(Ipv4(_)) => {
                                    stats.ipv4 += 1;
                                },
                                Some(Ipv6(_)) => {
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
                                None => {
                                    if value.net.is_some() {
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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = "Slices all packages of a or multiple pcap(s) to measure performance")]
struct Args {
    /// Input PCAP file or files (can be a glob expression)
    input: String,

    /// Resulting CSV
    result_csv: PathBuf,

    /// Number of times to greet
    #[arg(short, long, default_value_t = 1)]
    number_of_reads: usize,
}

fn main() {
    let args = Args::parse();
    let mut out_file = csv::Writer::from_path(args.result_csv).unwrap();

    for entry in glob::glob(&args.input).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                let path_str = path.to_str().unwrap();
                for _i in 0..args.number_of_reads {
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