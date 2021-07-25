extern crate etherparse;
use etherparse::*;

extern crate pcap;

struct Mac {
    addr: [u8;6]
}
impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.addr[0],
            self.addr[1],
            self.addr[2],
            self.addr[3],
            self.addr[4],
            self.addr[5],
        )
    }
}


fn main() {
    for device in pcap::Device::list().unwrap() {
        println!("{:?}", device);
    }
    println!("default: {:?}", pcap::Device::lookup());
    let mut cap = pcap::Capture::from_device(pcap::Device::lookup().unwrap()).unwrap()
                  .timeout(20)
                  .promisc(true)
                  .open().unwrap();

    loop {
        while let Ok(packet) = cap.next() {

            let sliced = SlicedPacket::from_ethernet(&packet);

            match sliced {
                Err(value) => {
                    println!("Err {:?}", value);
                    println!("  {:?}", &packet);
                },
                Ok(_) => {}
            }
        }
    }
}