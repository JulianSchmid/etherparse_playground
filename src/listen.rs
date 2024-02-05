use etherparse::*;

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
    let mut cap = pcap::Capture::from_device(pcap::Device::lookup().unwrap().unwrap()).unwrap()
                  .immediate_mode(true)
                  .open()
                  .unwrap();

    loop {
        while let Ok(packet) = cap.next_packet() {

            let sliced = SlicedPacket::from_ethernet(&packet);

            match sliced {
                Err(value) => println!("Err {:?}", value),
                Ok(value) => {

                    println!("Ok");
                    use LinkSlice::*;
                    use NetSlice::*;
                    use TransportSlice::*;
                    use VlanSlice::*;

                    match value.link {
                        Some(Ethernet2(value)) => println!("  Ethernet2 {} => {}", Mac{ addr: value.source()}, Mac{ addr: value.destination()}),
                        Some(EtherPayload(e)) => println!("  EtherPayload {:?}", e.ether_type),
                        None => {}
                    }

                    match value.vlan {
                        Some(SingleVlan(value)) => println!("  SingleVlan {:?}", value.vlan_identifier()),
                        Some(DoubleVlan(value)) => println!("  DoubleVlan {:?}, {:?}", value.outer().vlan_identifier(), value.inner().vlan_identifier()),
                        None => {}
                    }

                    match value.net {
                        Some(Ipv4(ipv4)) => println!("  Ipv4 {:?} => {:?}", ipv4.header().source_addr(), ipv4.header().destination_addr()),
                        Some(Ipv6(ipv6)) => println!("  Ipv6 {:?} => {:?}", ipv6.header().source_addr(), ipv6.header().destination_addr()),
                        None => {}
                    }

                    match value.transport {
                        Some(Udp(value)) => println!("  UDP {:?} -> {:?}", value.source_port(), value.destination_port()),
                        Some(Tcp(value)) => {
                            println!("  TCP {:?} -> {:?}", value.source_port(), value.destination_port());
                            if value.options().len() > 0 {
                                println!("    TCP Options: {:?}",value.options_iterator());
                            }
                        }
                        Some(Icmpv4(icmpv4)) => {
                            println!("  Icmp4 {:?}", icmpv4.icmp_type());
                        },
                        Some(Icmpv6(icmpv6)) => {
                            println!("  Icmp6 {:?}", icmpv6.header());
                        },
                        None => {}
                    }
                }
            }
        }
    }
}