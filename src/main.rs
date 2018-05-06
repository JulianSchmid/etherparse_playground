use std::io::{BufReader, BufWriter, Write};
use std::fs::File;
extern crate rpcap;
use self::rpcap::CapturedPacket;
use self::rpcap::read::PcapReader;
use self::rpcap::write::{PcapWriter, WriteOptions};
extern crate etherparse;
use self::etherparse::*;
use self::etherparse::EtherType::*;
use self::etherparse::IpTrafficClass;
use std::time::SystemTime;

extern crate byteorder;
use byteorder::ByteOrder;
use byteorder::BigEndian;


fn main() {
    let f: [u8;8] = [0,1,2,3, 4,5,6,7];
    println!("{:?}", (0..4).map(|i| BigEndian::read_u16(&f[i*2..i*2 + 2])).fold(0, |acc, x| acc + x));

    // read a PCAP file
    let mut pcapr = PcapReader::new(BufReader::new(File::open("test.pcap").unwrap())).unwrap();
    println!("linktype: {}", pcapr.get_linktype());
    println!("snaplen: {}", pcapr.get_snaplen());

    // copy all packets from example.pcap to copy.pcap
    while let Some(_packet) = pcapr.next().unwrap() {
        /*println!("packet at {:?} with size {} (cropped from {})",
            packet.time, packet.data.len(), packet.orig_len);
        let mut cursor = Cursor::new(&packet.data);
        println!("  {:?}", cursor.read_ethernet2_header());
        println!("  {:?}", cursor.read_ip_header());*/
    }

    let outfile = File::create("copy.pcap").unwrap();
    let writer = BufWriter::new(outfile);
    let mut pcapw = PcapWriter::new(writer, WriteOptions {
        snaplen: 0xfffff,
        linktype: pcapr.get_linktype(),
    }).unwrap();
    {
        let mut payload = Vec::new();
        Ethernet2Header {
            destination: [1,2,3,4,5,6],
            source: [10,11,12,13,14,15],
            ether_type: VlanTaggedFrame as u16,
        }.write(&mut payload).unwrap();
        SingleVlanHeader {
            ether_type: Ipv4 as u16,
            priority_code_point: 0,
            drop_eligible_indicator: true,
            vlan_identifier: 1234,
        }.write(&mut payload).unwrap();
        let ip_header = Ipv4Header::new(2*4 + 16, 4, IpTrafficClass::Udp, [192, 168, 1, 1], [212, 10, 11, 123]).unwrap();
        ip_header.write(&mut payload, &[]).unwrap();
        let udp_payload: [u8; 17] = [2;17]; 
        UdpHeader::with_ipv4_checksum(1234, 5678, &ip_header, &udp_payload).unwrap().write(&mut payload).unwrap();
        payload.write(&udp_payload).unwrap();
        pcapw.write(&CapturedPacket {
            time: SystemTime::now(),
            data: &payload[..],
            orig_len: payload.len(),
        }).unwrap();
    }
    {
        let udp_payload = [39,40,41,42,43];
        let mut packet = Vec::new();
        Ethernet2Header {
            destination: [1,2,3,4,5,6],
            source: [10,11,12,13,14,15],
            ether_type: Ipv6 as u16,
        }.write(&mut packet).unwrap();
        let ip_header = Ipv6Header {
            traffic_class: 1,
            flow_label: 0x81806,
            payload_length: (UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16,
            next_header: IpTrafficClass::Udp as u8,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8,
                     9,10,11,12,13,14,15,16],
            destination: [21,22,23,24,25,26,27,28,
                          29,30,31,32,33,34,35,36]
        };
        ip_header.write(&mut packet).unwrap();
        UdpHeader::with_ipv6_checksum(37, 38, &ip_header, &udp_payload).unwrap().write(&mut packet).unwrap();
        packet.write_all(&udp_payload).unwrap();
        pcapw.write(&CapturedPacket {
            time: SystemTime::now(),
            data: &packet[..],
            orig_len: packet.len(),
        }).unwrap();
    }
    {
        let mut packet = Vec::new();
        let udp_payload = [1,2,3,4,5,6,7,8];

        //Lets start out with an ethernet II header containing the mac addresses
        Ethernet2Header{
            destination: [1,2,3,4,5,6],
            source: [11,12,13,14,15,16],
            ether_type: EtherType::Ipv4 as u16
        }.write(&mut packet).unwrap();

        //create the ipv4 header with the helper function
        //Note: It is also possible to define the rest of the header values via Ipv4Header {...}
        let ip_header = Ipv4Header::new(
            //size of the payload
            UdpHeader::SERIALIZED_SIZE + udp_payload.len(),
            //time to live
            20,
            //contained protocol is udp
            IpTrafficClass::Udp,
            //source ip address
            [192,168,1,42],
            //destination ip address
            [192,168,1,1]
        ).unwrap();

        ip_header.write(&mut packet, &[]).unwrap();

        //write the udp header
        UdpHeader::with_ipv4_checksum(
            //source port
            0,
            //destination port
            42,
            //ip header
            &ip_header,
            //udp payload
            &udp_payload
        ).unwrap().write(&mut packet).unwrap();

        packet.write_all(&udp_payload).unwrap();

        pcapw.write(&CapturedPacket {
            time: SystemTime::now(),
            data: &packet[..],
            orig_len: packet.len(),
        }).unwrap();
    }
    {
        let mut packet = Vec::new();
        //Lets start out with an ethernet II header containing the mac addresses
        Ethernet2Header{
            destination: [1,2,3,4,5,6],
            source: [11,12,13,14,15,16],
            ether_type: EtherType::Ipv4 as u16
        }.write(&mut packet).unwrap();

        let mut payload = [0,0,0,0];
        let sum: u16 = IpTrafficClass::Udp as u16 +
                        (2*(UdpHeader::SERIALIZED_SIZE as u16 + 
                            payload.len() as u16));
        BigEndian::write_u16(&mut payload, 0xffff - sum);
        let ip_header = Ipv4Header::new(
            UdpHeader::SERIALIZED_SIZE + payload.len(), 
            5, 
            IpTrafficClass::Udp, 
            [0,0,0,0],
            [0,0,0,0]).unwrap();
        ip_header.write(&mut packet, &[]).unwrap();

        UdpHeader::with_ipv4_checksum(0, 0, &ip_header, &payload).unwrap().write(&mut packet).unwrap();
        packet.write_all(&payload).unwrap();
        pcapw.write(&CapturedPacket {
            time: SystemTime::now(),
            data: &packet[..],
            orig_len: packet.len(),
        }).unwrap();
    }
    {
        let mut packet = Vec::new();

        let udp_payload_len = 0xffff
                              - (Ipv4Header::SERIALIZED_SIZE as usize)
                              - (UdpHeader::SERIALIZED_SIZE as usize);
        println!("payload len = {:?}", udp_payload_len);
        let mut udp_payload = Vec::with_capacity(udp_payload_len);
        udp_payload.resize(udp_payload_len, 0xff);

        Ethernet2Header{
            destination: [1,2,3,4,5,6],
            source: [11,12,13,14,15,16],
            ether_type: EtherType::Ipv6 as u16
        }.write(&mut packet).unwrap();

        let ip_header = Ipv6Header {
            traffic_class: 1,
            flow_label: 0x81806,
            payload_length: (UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16,
            next_header: IpTrafficClass::Udp as u8,
            hop_limit: 40,
            source: [0xff;16],
            destination: [0xff;16]
        };

        ip_header.write(&mut packet).unwrap();
        UdpHeader::with_ipv6_checksum(0xffff, 
                                      0xffff, 
                                      &ip_header,
                                      &udp_payload).unwrap().write(&mut packet).unwrap();
        packet.write_all(&udp_payload).unwrap();
        for _i in 0..1000 {
            pcapw.write(&CapturedPacket {
                time: SystemTime::now(),
                data: &packet[..],
                orig_len: packet.len(),
            }).unwrap();
        }
    }
}
