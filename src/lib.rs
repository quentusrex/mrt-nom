#[macro_use]
extern crate nom;
extern crate ipnet;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::fs::File;
use std::io::Read;
use flate2::bufread::GzDecoder;
use nom::{IResult};
//use nom::combinator::rest;
use nom::number::complete::{be_u8, be_u16, be_u32};
//use nom::bytes::complete::take;
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
    Origin(BGPAttrOrigin),
    AsPath(BGPAttrAsPath),
    NextHop(IpAddr),
//    MULTI_EXIT_DISC,
    LocalPref(u32),
    AtomicAggregator, // 6
    Aggregator(BGPAttrAggregator), // 7
    Community(BGPAttrCommunity), // 8
    MultiprotocolReachableNLRI(BGPAttrMPReachableNLRI), // 14
    MultiprotocolUnreachableNLRI(BGPAttrMPUnreachableNLRI), // 15
    ExtendedCommunity(BGPAttrExtendedCommunity), // 16
    ConnectorAttribute(BGPAttrConnector), // 20 deprecated
    AsPathLimit(BGPAttrAsPathLimit), // 21 deprecated
    LargeCommunity(BGPAttrLargeCommunity), // 32
    ReservedDevelopment(BGPAttrReservedDevelopment) // 255
}

#[derive(Debug)]
pub struct BGPAttrLargeCommunity {
    pub global_admin: u32,
    pub part_one: u32,
    pub part_two: u32
}

// TODO: Break out all community handling into a top level Enum, with substructures. 
#[derive(Debug)]
pub enum ExtendedCommunity {
    TwoOctetAS,
    IPv4AddrSpecific,
    Opaque,
}

#[derive(Debug)]
pub struct BGPAttrExtendedCommunity {
    pub high: u8,
    pub low: u8,
    pub value: Vec<u8>
}

#[derive(Debug)]
pub struct BGPAttrAsPathLimit {
    pub len: u8,
    pub asn: u32,
}

#[derive(Debug)]
pub struct BGPAttrCommunity {
    pub asn: u16,
    pub value: u16
}


#[derive(Debug)]
pub struct BGPAttrAggregator {
    pub asn: u16,
    pub ip: Ipv4Addr
}

#[derive(Debug)]
pub struct BGPAttrReservedDevelopment {
    pub value: Vec<u8>
}

#[derive(Debug)]
pub struct BGPAttrConnector {
    pub value: Vec<u8>
}


#[derive(Debug)]
pub struct BGPAttrAsPath {
//    pub optional: bool,   // bit 0
//    pub transitive: bool, // bit 1
//    pub partial: bool,    // bit 2
//    pub xtended_length: bool, // bit 3
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

#[derive(Debug)]
pub enum BGPAttrOrigin {
    IGP,
    EGP,
    INCOMPLETE
}

#[derive(Debug)]
pub struct BGPAttrMPReachableNLRI {
    pub afi: u16,
    pub safi: u8,
    pub next_hop: IpAddr,
    pub prefix: IpNet
}

impl From<&[u8]> for BGPAttrMPReachableNLRI {
    fn from(input: &[u8]) -> Self {
        parse_mp_reachable_nlri(input).unwrap().1
    }
}

#[derive(Debug)]
pub struct BGPAttrMPUnreachableNLRI {
    pub afi: u16,
    pub safi: u8,
    pub withdrawn_routes: Vec<u8>
}

impl From<&[u8]> for BGPAttrMPUnreachableNLRI {
    fn from(input: &[u8]) -> Self {
        parse_mp_unreachable_nlri(input).unwrap().1
    }
}

impl From<u8> for BGPAttrOrigin {
    fn from(input: u8) -> Self {
        match input {
            0 => BGPAttrOrigin::IGP,
            1 => BGPAttrOrigin::EGP,
            2 => BGPAttrOrigin::INCOMPLETE,
            _ => {
                unimplemented!("Unknown BGP origin type: {}", input);
            }
        }
    }
}



impl From<&[u8]> for BGPAttrAsPathLimit {
    fn from(input: &[u8]) -> Self {
        parse_as_path_limit(input).unwrap().1
    }
}

impl From<&[u8]> for BGPAttrLargeCommunity {
    fn from(input: &[u8]) -> Self {
        parse_large_communities(input).unwrap().1
    }
}

impl From<&[u8]> for BGPAttrExtendedCommunity {
    fn from(input: &[u8]) -> Self {
        parse_extended_communities(input).unwrap().1
    }
}

impl From<&[u8]> for BGPAttrReservedDevelopment {
    fn from(input: &[u8]) -> Self {
        BGPAttrReservedDevelopment{ value: input.to_vec() }
    }
}

impl From<&[u8]> for BGPAttrConnector {
    fn from(input: &[u8]) -> Self {
        BGPAttrConnector{ value: input.to_vec() }
    }
}

impl From<&[u8]> for BGPAttrCommunity {
    fn from(input: &[u8]) -> Self {
        parse_bgp_communities(input).unwrap().1
    }
}

impl From<&[u8]> for BGPAttrAggregator {
    fn from(input: &[u8]) -> Self {
        parse_bgp_aggregator(input).unwrap().1
    }
}

impl From<(u8, bool, bool, bool, &[u8])> for BGPAttr {
    fn from(input: (u8, bool, bool, bool, &[u8])) -> Self {
        let (i, o, t, p, d) = input;
        // https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml
        match i {
            1 => BGPAttr::Origin(d[0].into()),            
            2 => {
                let (_, resp) = parse_extended_as_path(d).unwrap();
                let (_segment_type, _segment_len, asns) = resp;
                BGPAttr::AsPath(BGPAttrAsPath{
                    as_path: asns
                })
            },
            3 => {
                let raw = d.to_vec();
                if raw.len() > 4 {
                    unimplemented!("Next Hop not implemented for ipv6: {:?}", raw);
                }
                let ip_addr = IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(raw.try_into().expect("incorrect ipv4 length") )));

                BGPAttr::NextHop(ip_addr)
            },
            4 => {
                let pref = u32::from_be_bytes(d.try_into().expect("incorrect ipv4 length"));
                BGPAttr::LocalPref(pref)
            },
            // Deprecated attribute, but does carry a payload, that is going to be ignored until added here.
            6 => BGPAttr::AtomicAggregator,
            7 => BGPAttr::Aggregator(d.into()),
            8 => BGPAttr::Community(d.into()),
            14 => BGPAttr::MultiprotocolReachableNLRI(d.into()),
            15 => BGPAttr::MultiprotocolUnreachableNLRI(d.into()),
            16 => BGPAttr::ExtendedCommunity(d.into()), 
            20 => BGPAttr::ConnectorAttribute(d.into()),
            21 => BGPAttr::AsPathLimit(d.into()),
            32 => BGPAttr::LargeCommunity(d.into()),
            255 => BGPAttr::ReservedDevelopment(d.into()),
            /* 
             */
            _ => {
                
                unimplemented!("Unknown BGPAttrType: {} optional: {} transitive: {} partial: {} data: {:?}", i, o, t, p, d);
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

fn parse_as_path_limit(i: &[u8]) -> IResult<&[u8], BGPAttrAsPathLimit> {
    do_parse!(i,
              len: be_u8 >>
              asn: be_u32 >> 
              ( BGPAttrAsPathLimit{
                  len: len,
                  asn: asn
              })
        )
}

fn parse_large_communities(i: &[u8]) -> IResult<&[u8], BGPAttrLargeCommunity> {
    do_parse!(i,
              admin: be_u32 >>
              one: be_u32 >>
              two: be_u32 >>
              ( BGPAttrLargeCommunity{
                  global_admin: admin,
                  part_one: one,
                  part_two: two
              })
        )
}

fn parse_extended_communities(i: &[u8]) -> IResult<&[u8], BGPAttrExtendedCommunity> {
    do_parse!(i,
              high: be_u8 >>
              low: be_u8 >>
              value: take!(6) >>
              ( BGPAttrExtendedCommunity{
                  high: high,
                  low: low,
                  value: value.to_vec()
              })
        )
}

fn parse_bgp_aggregator(i: &[u8]) -> IResult<&[u8], BGPAttrAggregator> {
    do_parse!(i,
              asn: be_u16 >>
              ip: be_u32 >>
              ( BGPAttrAggregator{
                  asn: asn,
                  ip: Ipv4Addr::from(ip)
              })
        )
}

fn parse_bgp_communities(i: &[u8]) -> IResult<&[u8], BGPAttrCommunity> {
    do_parse!(i,
              asn: be_u16 >>
              value: be_u16 >>
              ( BGPAttrCommunity{
                  asn: asn,
                  value: value
              })
        )
}

fn parse_bgp_attributes(i: &[u8]) -> IResult<&[u8], Vec<BGPAttr>> {
    many1!(i, parse_bgp_attribute)
}

fn parse_bgp_attribute(i: &[u8]) -> IResult<&[u8], BGPAttr> {
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

fn parse_mp_unreachable_nlri(input: &[u8]) -> IResult<&[u8], BGPAttrMPUnreachableNLRI> {
    //dbg!(input);
    do_parse!(input,
              address_family_id: be_u16 >>
              subsequent_address_family_id: be_u8 >>
              nlri_len_bits: be_u8 >>
              nlri: take!((nlri_len_bits + 7) / 8) >>
              ({
                  BGPAttrMPUnreachableNLRI{
                      afi: address_family_id,
                      safi: subsequent_address_family_id,
                      withdrawn_routes: nlri.to_vec()
                  }
              })
    )
}

fn parse_mp_reachable_nlri(input: &[u8]) -> IResult<&[u8], BGPAttrMPReachableNLRI> {
    //dbg!(input);
    do_parse!(input,
              address_family_id: be_u16 >>
              subsequent_address_family_id: be_u8 >>
              next_hop_len: be_u8 >>
              next_hop_raw: take!(next_hop_len) >>
              next_hop: value!({
                  match address_family_id {
                      1 => {
                          let mut addr = vec![0u8; 4];
                          addr.copy_from_slice(&next_hop_raw);
                          IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(addr.try_into().expect("incorrect ipv4 length"))))
                      },
                      2 => {
                          let mut addr = vec![0u8; 16];
                          addr.copy_from_slice(&next_hop_raw);
                          IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(addr.try_into().expect("incorrect ipv6 length") )))
                      },
                      _ => { unimplemented!("Unknown MP Reachable NLRI with AFI {} SAFI {} and prefix_raw: {:?}",
                                            address_family_id, subsequent_address_family_id, next_hop_raw )}
                  }
              }) >>
              _reserved: take!(1) >>
              nlri_len: be_u8 >>
              prefix_raw: take!((nlri_len + 7) / 8) >>
              prefix: value!({
                  match address_family_id {
                      1 => {
                          let addr = Ipv4Addr::from(u32::from_be_bytes(prefix_raw.try_into().expect("incorrect ipv4 length") ));
                          IpNet::V4(Ipv4Net::new(addr, nlri_len).expect("Invalid ipv4 network or prefix")) },
                      2 => {
                          let mut addr = vec![0u8; 16];
                          addr[..((nlri_len + 7) / 8) as usize].copy_from_slice(&prefix_raw);                          
                          let ip = Ipv6Addr::from(u128::from_be_bytes(addr.try_into().expect("incorrect ipv6 length") ));
                          IpNet::V6(Ipv6Net::new(ip, nlri_len).expect("Invalid ipv6 network or prefix")) },
                      _ => { unimplemented!("Unknown MP Reachable NLRI with AFI {} SAFI {} and prefix_raw: {:?}",
                                            address_family_id, subsequent_address_family_id, prefix_raw )}
                  }
              }) >>
              (
                  BGPAttrMPReachableNLRI {
                      afi: address_family_id,
                      safi: subsequent_address_family_id,
                      next_hop: next_hop,
                      prefix: prefix
                  }
              ))
}

fn parse_extended_as_path(input: &[u8]) -> IResult<&[u8], (u8, u8, Vec<u32>)> {
    // dbg!(input);
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
        (16, 4) => { // BGP4MP , BGP4MP_MESSAGE_AS4
            dbg!(input);
            unimplemented!("Major {} subtype {} Data: {:?}", major, subtype, input)
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
