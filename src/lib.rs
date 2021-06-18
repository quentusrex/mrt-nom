#[macro_use]
extern crate nom;
extern crate ipnet;

use ipnet::{Ipv4Net, Ipv6Net};
use std::fs::File;
use std::io::Read;
use flate2::bufread::GzDecoder;
use nom::{IResult, take_bits};
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::bytes::complete::take;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct MrtFile {
    records: Vec<MrtRecord>,
}

#[derive(Debug)]
pub struct MrtRecord {
    pub timestamp: u32,
    pub mrt_type: MrtType,
    pub subtype: MrtSubType,
//    pub length: u32,
    pub message: MrtMessage
}

#[derive(Debug)]
pub enum MrtMessage {
    // table_dump_v2
    PeerIndexTable(MrtPeerIndexTable),
    RIBIPv4Unicast(MrtRIBIPv4Unicast),
    // 3 RIB_IPV6_UNICAST
    RIBIPv6Unicast(MrtRIBIPv6Unicast),
    // 5 RIB_IPV6_MULTICAST
    // 6 RIB_GENERIC
}

#[derive(Debug)]
pub struct MrtPeerIndexTable {
    pub collector_bgp_id: u32,
    pub view_name: String,
    pub peers: Vec<MrtIndexTablePeer>
}

#[derive(Debug)]
pub struct MrtIndexTablePeer {
//    pub ipv6: bool,
    pub bgp_id: u32,
    pub ip: IpAddr,
    pub asn: u32
}

#[derive(Debug)]
pub struct MrtRIBIPv4Unicast {
    pub sequence: u32,
//    pub prefix_len: u8,
    pub prefix: Ipv4Net,
    pub rib_entries: Vec<MrtRIBEntry>
}


#[derive(Debug)]
pub struct MrtRIBIPv6Unicast {
    pub sequence: u32,
//    pub prefix_len: u8,
    pub prefix: Ipv6Net,
    pub rib_entries: Vec<MrtRIBEntry>
}

#[derive(Debug)]
pub struct MrtRIBEntry {
    pub peer_index: u16,
    pub orig_time: u32,
    pub bgp_attributes: Vec<BGPAttr>
}

// TODO: convert the type code for BGPAttr into an enum, and handle the type code data properly.
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2
#[derive(Debug)]
pub enum BGPAttr {
    ORIGIN,
    AsPath(BGPAttrAsPath),
    NEXT_HOP,
//    MULTI_EXIT_DISC,
    LOCAL_PREF,
    AtomicAggregator, // 6
    Aggregator, // 7
    Community, // 8
    MultiprotocolReachableNLRI, // 14
    MultiprotocolUnreachableNLRI, // 15
    ExtendedCommunities, // 16
    ConnectorAttribute, // 20 deprecated
    AsPathLimit, // 21 deprecated
    LargeCommunity, // 32
    ReservedDevelopment // 255
}

#[derive(Debug)]
pub struct BGPAttrAsPath {
//    pub optional: bool,   // bit 0
//    pub transitive: bool, // bit 1
//    pub partial: bool,    // bit 2
//    pub extended_length: bool, // bit 3
    pub as_path: Vec<u32>
}

#[derive(Debug)]
pub enum MrtType {
    UNKNOWN,
    OSPFv2,
    TableDump,
    TableDumpV2,
}

#[derive(Debug)]
pub enum MrtSubType {
    UNKNOWN,
    PeerIndexTable,
    RIBIPv4Unicast,
    RIBIPv4Multicast,
    RIBIPv6Unicast,
    RIBIPv6Multicast,
    RIBGeneric
}

impl From<(u8, bool, bool, bool, &[u8])> for BGPAttr {
    fn from(input: (u8, bool, bool, bool, &[u8])) -> Self {
        let (i, _o, _t, _p, d) = input;
        match i {
            1 => BGPAttr::ORIGIN,
            2 => {
                let (_, resp) = parse_extended_as_path(d).unwrap();
                let (segment_type, segment_len, asns) = resp;
                BGPAttr::AsPath(BGPAttrAsPath{
                    as_path: asns
                })
            },
            3 => BGPAttr::NEXT_HOP,
            4 => BGPAttr::LOCAL_PREF,
            6 => BGPAttr::AtomicAggregator,
            7 => BGPAttr::Aggregator,
            8 => BGPAttr::Community,
            14 => BGPAttr::MultiprotocolReachableNLRI,
            15 => BGPAttr::MultiprotocolUnreachableNLRI,
            16 => BGPAttr::ExtendedCommunities,
            20 => BGPAttr::ConnectorAttribute,
            21 => BGPAttr::AsPathLimit,
            32 => BGPAttr::LargeCommunity,
            255 => BGPAttr::ReservedDevelopment,
            _ => {
                unimplemented!("Unknown BGPAttrType: {}", i);                
            }
        }
    }
}

impl From<u16> for MrtType {
    fn from(i: u16) -> Self {
        match i {
            11 => MrtType::OSPFv2,
            12 => MrtType::TableDump,
            13 => MrtType::TableDumpV2,
            _ => {
                println!("Unknown MrtType: {}", i);
                MrtType::UNKNOWN
            }
        }
    }
}

impl From<(u16, u16)> for MrtSubType {
    fn from(i: (u16, u16)) -> Self {
        let (m, s) = i;
        match (m, s) {
            // TABLE_DUMP_V2
            (13, 1) => MrtSubType::PeerIndexTable,
            (13, 2) => MrtSubType::RIBIPv4Unicast,
            (13, 3) => MrtSubType::RIBIPv4Multicast,
            (13, 4) => MrtSubType::RIBIPv6Unicast,
            (13, 5) => MrtSubType::RIBIPv6Multicast,
            (13, 6) => MrtSubType::RIBGeneric,
            
            _ => {
                println!("Unknown MrtSubType: {:?}", i);
                MrtSubType::UNKNOWN
            }
        }
    }
}

// named!(peer_type<(&[u8], usize), (u8, u8, u8)>, tuple!(take_bits!(6), take_bits!(1), take_bits!(1)) );

fn parse_bgp_attributes(i: &[u8]) -> IResult<&[u8], Vec<BGPAttr>> {
    many1!(i, parse_bgp_attribute)
}

fn parse_bgp_attribute(i: &[u8]) -> IResult<&[u8], BGPAttr> {
    //dbg!(i);
    // unimplemented!("RIB Entry");
    do_parse!(i,
              flags: be_u8 >>
              code: be_u8 >>
              optional:   value!((flags & 0b1000_0000) >= 1) >>
              transitive: value!((flags & 0b0100_0000) >= 1) >>
              partial:    value!((flags & 0b0010_0000) >= 1) >>
              extended_length: value!((flags & 0b0001_0000) >= 1) >>
              len_raw: switch!( value!( extended_length ), // Extended length attribute
                                true => take!(2) |
                                false => take!(1) ) >>
              len: value!( match extended_length {
                  true => { u16::from_be_bytes(len_raw.try_into().expect("failed to get correct len for bgp attr"))},
                  false => { u8::from_be_bytes(len_raw.try_into().expect("failed to get correct len for bgp attr")) as u16}
              }) >> 
              attr: take!(len) >>
              ({
                  let attr_type: BGPAttr = (code, optional, transitive, partial, attr).into();
                  attr_type
              })
    )
}

fn parse_extended_as_path(input: &[u8]) -> IResult<&[u8], (u8, u8, Vec<u32>)> {
    dbg!(input);
    do_parse!(input,
              segment_type: be_u8 >>
              segment_length: be_u8 >>
              asns: length_count!(value!(segment_length), be_u32) >>
              (
                  (segment_type, segment_length, asns)
              ))
}

fn parse_rib_entry(i: &[u8]) -> IResult<&[u8], MrtRIBEntry> {
    // dbg!(i);
    do_parse!(i,
              peer_index: be_u16 >>
              orig_time: be_u32 >>
              attr_len: be_u16 >>
              data: take!(attr_len) >>
              // attrs: length_count!(be_u16, parse_bgp_attribute) >>
              (MrtRIBEntry{
                  peer_index: peer_index,
                  orig_time: orig_time,
                  bgp_attributes: parse_bgp_attributes(data).unwrap().1
              })
    )
}

fn parse_index_table_peer(i: &[u8]) -> IResult<&[u8], MrtIndexTablePeer> {
    do_parse!(i,
              peer_type: take!(1) >> 
//              pad1: be_u8 >>
//              pad2: be_u16 >>
              bgp_id: be_u32 >>
              addr_len: value!(match ((peer_type[0] as u8) & 0b0000_0001) >= 1 {
                  true => { 16 },
                  false => { 4 },
              }) >>
              asn_len: value!(match ((peer_type[0] as u8) & 0b0000_0010) >= 1 {
                  true => { 4 },
                  false => { 2 },
              }) >> 
              addr_raw: take!(addr_len) >> 
              asn_raw: take!(asn_len) >>
              addr: value!(match ((peer_type[0] as u8) & 0b0000_0001) >= 1 {
                  true => { IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(addr_raw.try_into().expect("incorrect ipv6 length") ))) },
                  false => { IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(addr_raw.try_into().expect("incorrect ipv4 length") ))) }
              }) >>
              asn: value!(match ((peer_type[0] as u8) & 0b0000_0010) >= 1 {
                  true => { u32::from_be_bytes(asn_raw.try_into().expect("Failed to get correct length for asn")) },
                  false => { u16::from_be_bytes(asn_raw.try_into().expect("Failed to get correct length for asn")) as u32}
              }) >>
              
              (MrtIndexTablePeer{
                  // ipv6: ((peer_type[0] as u8) & 0b0000_0001) >= 1,
                  bgp_id: bgp_id,
                  ip: addr,
                  asn: asn  // {if asn_large == 0 { asn2.unwrap().into() } else { asn4.unwrap() }}
                  
              }))
}

fn parse_message(major: u16, subtype: u16, input: &[u8]) -> IResult<&[u8], MrtMessage> {
    match (major, subtype) {
        (13, 1) => {
            do_parse!(input,
                      id: be_u32 >>
                      name_len: be_u16 >>
                      name: take!(name_len) >>
                      peers: length_count!(be_u16, parse_index_table_peer) >>
                      (MrtMessage::PeerIndexTable(MrtPeerIndexTable{
                          collector_bgp_id: id,
                          view_name: String::from_utf8(name.clone().to_vec()).unwrap(),
                          peers: peers
                      }))
            )                      
        },        
        (13, 2) => { // RIB_IPV4_UNICAST
            do_parse!(input,
                      seq: be_u32 >>
                      prefix_len: be_u8 >>
                      prefix_raw: take!( (prefix_len + 7) / 8 ) >>
                      prefix: value!({
                          let mut addr = vec![0u8; 4];
                          addr[.. ((prefix_len + 7) / 8) as usize].copy_from_slice(&prefix_raw);
                          Ipv4Net::new(Ipv4Addr::from(u32::from_be_bytes(addr.try_into().expect("incorrect ipv4 length"))), prefix_len).unwrap()
                      }) >>
                      entries: length_count!(be_u16, parse_rib_entry) >>
                      (MrtMessage::RIBIPv4Unicast(MrtRIBIPv4Unicast{
                          sequence: seq,
                          //prefix_len: prefix_len,
                          prefix: prefix,
                          rib_entries: entries 
                      }))
            )                      
        },
        (13, 4) => { // RIB_IPV6_UNICAST
            // dbg!(input);
            // unimplemented!("RIB IPv6");
            do_parse!(input,
                      seq: be_u32 >>
                      prefix_len: be_u8 >>
                      prefix_raw: take!( (prefix_len + 7) / 8 ) >>
                      prefix: value!({
                          let mut addr = vec![0u8; 16];
                          addr[.. ((prefix_len + 7) / 8) as usize].copy_from_slice(&prefix_raw);
                          Ipv6Net::new(Ipv6Addr::from(u128::from_be_bytes(addr.try_into().expect("incorrect ipv6 length") )), prefix_len).unwrap()
                      }) >>
                      entries: length_count!(be_u16, parse_rib_entry) >>
                      (MrtMessage::RIBIPv6Unicast(MrtRIBIPv6Unicast{
                          sequence: seq,
                          //prefix_len: prefix_len,
                          prefix: prefix,
                          rib_entries: entries
                      }))
            )                      
        }
        
        _ => {
            dbg!(input);
            unimplemented!("Major {} subtype {} Data: {:?}", major, subtype, input)
        }
    }
}

fn parse_record(input: &[u8]) -> IResult<&[u8], MrtRecord> {
    do_parse!(input, 
              timestamp: be_u32 >>
              major_type: be_u16 >>
              sub_type: be_u16 >>
              length: be_u32 >>
              message: take!(length) >> 
              (MrtRecord{ timestamp: timestamp,
                          mrt_type: major_type.into(),
                          subtype: (major_type, sub_type).into(),
                          //length: length,
                          message: parse_message(major_type, sub_type, message).unwrap().1
              })
    ) //.map(|_, res| res)
}

fn parse_records(input: &[u8]) -> IResult<&[u8], Vec<MrtRecord>> {
    many1!(input, parse_record)
}

pub fn read_gz_file(path: &str) -> Result<MrtFile, std::io::Error> {
    let mut compressed = File::open(path).expect("Failed to open file");
    let mut compressed_buff = Vec::new();

    compressed.read_to_end(&mut compressed_buff).expect("Failed to read gz file");

    let mut gz = GzDecoder::new(compressed_buff.as_slice()).expect("Failed to create Gz Decoder for file contents");
    let mut decompressed_buff = Vec::new();

    println!("Header: {:?}", gz.header());

    gz.read_to_end(&mut decompressed_buff).expect("Failed to fully decompress input file");
    
    let (_, record) = parse_records(decompressed_buff.as_slice()).expect("Failed to parse decompressed file contents");
    println!("Record: {:?}", record);
    let results = MrtFile{ records: record };
    
    Ok(results)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
