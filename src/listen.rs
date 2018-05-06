extern crate etherparse;
use etherparse::*;
extern crate pcap;
extern crate futures;
extern crate tokio_core;
use std::io::Cursor;

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
            let mut cursor = Cursor::new(packet.data);

            //decode ethernet II framea
            match Ethernet2Header::read(&mut cursor) {
                Ok(eth) => {
                    match EtherType::from_u16(eth.ether_type) {
                        //decode ip frame
                        Some(EtherType::Ipv4) | Some(EtherType::Ipv6) => {
                            //decode ip message
                            let ip_header = IpHeader::read(&mut cursor);
                            println!("{:?}", ip_header)

                            //check protocol type
                            //todo
                        },

                        //unknown ethernet type type
                        None => println!("unknown ethernet type({:?})", eth.ether_type),

                        //other know type which we dont know how to decode
                        ether_type => println!("{:?}", ether_type)
                    }
                },
                Err(value) => {
                    println!("ethernetII: failed to decode => {:?}", value);
                }
            }
        }
    }
}