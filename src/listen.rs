extern crate etherparse;
use etherparse::*;
extern crate pcap;


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
                Err(value) => println!("Err {:?}", value),
                Ok(value) => {
                    println!("Ok");
                    use LinkSlice::*;
                    use InternetSlice::*;
                    use TransportSlice::*;
                    use VlanSlice::*;

                    match value.link {
                        Some(Ethernet2(value)) => println!("  Ethernet2 {:?} => {:?}", value.source(), value.destination()),
                        None => {}
                    }

                    match value.vlan {
                        Some(SingleVlan(value)) => println!("  SingleVlan {:?}", value.vlan_identifier()),
                        Some(DoubleVlan(value)) => println!("  DoubleVlan {:?}, {:?}", value.outer().vlan_identifier(), value.inner().vlan_identifier()),
                        None => {}
                    }

                    match value.ip {
                        Some(Ipv4(value)) => println!("  Ipv4 {:?} => {:?}", value.source_addr(), value.destination_addr()),
                        Some(Ipv6(value, _)) => println!("  Ipv6 {:?} => {:?}", value.source_addr(), value.destination_addr()),
                        None => {}
                    }

                    match value.transport {
                        Some(Udp(value)) => println!("  UDP {:?} -> {:?}", value.source_port(), value.destination_port()),
                        None => {}
                    }
                }
            }

            /*let decoded = PacketHeaders::decode(&packet);
            use IpHeader::*;
            use std::net::{Ipv4Addr, Ipv6Addr};
            match decoded {
                Ok(value) => {
                    match value.ethernet {
                        Some(value) => {
                            match EtherType::from_u16(value.ether_type) {
                                Some(ether_type) => println!("EthernetII({:?}) {:?} => {:?}", ether_type, value.source, value.destination),
                                None => println!("EthernetII({:?}) {:?} => {:?}", value.ether_type, value.source, value.destination)
                            }
                            
                        },
                        None => {}
                    }
                    match value.vlan {
                        Some(value) => {
                            println!("{:?}", value)
                        },
                        None => {}
                    }
                    match value.ip {
                        Some(Version4(value)) => {
                            println!("IPv4 {:?} => {:?}", Ipv4Addr::from(value.source), Ipv4Addr::from(value.destination));
                        },
                        Some(Version6(value)) => {
                            println!("IPv6 {:?} => {:?}", Ipv6Addr::from(value.source), Ipv6Addr::from(value.destination));
                        },
                        _ => {}
                    }
                    match value.transport {
                        Some(value) => {
                            println!("UDP {:?} => {:?}", value.source_port, value.destination_port);
                        },
                        None => {}
                    }
                },
                value => println!("{:?}", value)
            }
            println!("");*/
        }
    }
}