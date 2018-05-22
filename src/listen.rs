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
            for element in PacketSlicer::ethernet2(&packet) {
                use PacketSliceType::*;
                match element {
                    Ok(value) => {
                        match value {
                            Ethernet2Header(slice) => {
                                println!("Ethernet2 {:?} => {:?}", slice.source(), slice.destination());
                            },
                            SingleVlanHeader(slice) => {
                                println!("Vlan {:?}", slice.vlan_identifier());
                            },
                            DoubleVlanHeader(slice) => {
                                println!("Double Vlan {:?}, {:?}", slice.outer().vlan_identifier(), slice.inner().vlan_identifier());
                            },
                            Ethernet2Payload(ether_type, _payload) => {
                                println!("Ethernet2 unknown payload (ether_type: {:?})", ether_type);
                            },
                            Ipv4Header(slice) => {
                                println!("IPv4 {:?} => {:?}", slice.source_addr(), slice.destination_addr());
                            },
                            Ipv6Header(slice) => {
                                println!("IPv6 {:?} => {:?}", slice.source_addr(), slice.destination_addr());
                            },
                            Ipv6ExtensionHeader(header_type, _slice) => {
                                println!("IPv6 Extension Header {:?}", header_type);
                            },
                            IpPayload(protocol, _payload) => {
                                println!("IP unknown payload (id: {:?})", protocol);
                            },
                            UdpHeader(slice) => {
                                println!("UDP {:?} -> {:?}", slice.source_port(), slice.destination_port());
                            },
                            UdpPayload(_payload) => {

                            },
                        }
                    },
                    Err(value) => {
                        println!("Err {:?}", value);
                    }
                }
            }
            println!();


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