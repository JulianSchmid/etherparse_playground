#[macro_use]
extern crate serde_derive;
extern crate rpcap;
extern crate time;
use time::PreciseTime;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Stats {
    pub total_payload_size: usize,
    pub ok: usize,
    pub err: usize,
    pub eth_payload: usize,
    pub ipv4: usize,
    pub ipv6: usize,
    pub ip_payload: usize,
    pub udp: usize,
    pub tcp: usize,
    pub tcp_options_err: usize,
    pub tcp_options_nop: usize,
    pub tcp_options_max_seg: usize,
    pub tcp_options_window_scale: usize,
    pub tcp_options_selec_ack_perm: usize,
    pub tcp_options_selec_ack: usize,
    pub tcp_options_timestamp: usize
}

pub struct StatsRecorder<'a> {
    start: time::PreciseTime,
    pub stats: Stats,
    path: &'a str,
    file_size: u64
}

impl<'a> StatsRecorder<'a> {
    pub fn new(file_path: &'a str) -> StatsRecorder<'a> {
        let file_meta = std::fs::metadata(file_path).unwrap();
        StatsRecorder {
            start: PreciseTime::now(),
            stats: Default::default(),
            path: file_path,
            file_size: file_meta.len()
        }
    }

    pub fn end(self) -> ResultStats<'a> {
        let duration = self.start.to(PreciseTime::now()).to_std().unwrap();
        let duration_secs = duration.as_secs() as f64 + duration.subsec_nanos() as f64 * 1e-9;
        let gigabytes_per_sec_file = self.file_size as f64 / duration_secs /  1_000_000_000.0;
        let gigabytes_per_sec_packets = self.stats.total_payload_size as f64 / duration_secs / 1_000_000_000.0;

        println!("{}", self.path);
        println!("{:?}", self.stats);
        println!("{:?}", duration);
        println!("{:?}GB/s (file)", gigabytes_per_sec_file);
        println!("{:?}GB/s (packets data)", gigabytes_per_sec_packets);

        ResultStats {
            path: self.path,
            duration_secs: duration_secs,
            file_size: self.file_size,
            total_packets_size: self.stats.total_payload_size,
            gigabytes_per_sec_file: gigabytes_per_sec_file,
            gigabytes_per_sec_packets: gigabytes_per_sec_packets
        }
    }
}

#[derive(Serialize)]
pub struct ResultStats<'a> {
    pub path: &'a str,
    pub duration_secs: f64,
    pub file_size: u64,
    pub total_packets_size: usize,
    pub gigabytes_per_sec_file: f64,
    pub gigabytes_per_sec_packets: f64
}

#[derive(Debug)]
pub enum Error {
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
