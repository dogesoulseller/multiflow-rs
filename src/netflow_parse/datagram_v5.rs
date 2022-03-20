use std::net::Ipv4Addr;
use nom::IResult;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::sequence::tuple;

#[derive(Debug, Clone, Copy)]
pub struct NetflowDatagramV5Record {
	pub src_ip: Ipv4Addr,
	pub dst_ip: Ipv4Addr,
	pub next_hop_ip: Ipv4Addr,
	pub snmp_in_if_idx: u16,
	pub snmp_out_if_idx: u16,
	pub flow_packets: u32,
	pub flow_octets: u32,
	pub start_sys_uptime: u32,
	pub end_sys_uptime: u32,
	pub src_port: u16,
	pub dst_port: u16,
	_pad0: u8,
	pub tcp_flags: u8,
	pub ip_protocol: u8,
	pub ip_tos: u8,
	pub src_asn: u16,
	pub dst_asn: u16,
	pub src_mask: u8,
	pub dst_mask: u8,
	_pad1: u16,
}

fn parse_ipv4_addr(input: &[u8]) -> IResult<&[u8], Ipv4Addr> {
	let (res, ip_int) = be_u32(input)?;

	Ok((res, Ipv4Addr::from(ip_int)))
}

impl NetflowDatagramV5Record {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], NetflowDatagramV5Record> {
		let (res, (src_ip, dst_ip, next_hop_ip, snmp_in_if_idx, snmp_out_if_idx, flow_packets, flow_octets,
			start_sys_uptime, end_sys_uptime, src_port, dst_port, _pad0, tcp_flags, ip_protocol, ip_tos, src_asn, dst_asn, src_mask, dst_mask, _pad1))
			= tuple((parse_ipv4_addr, parse_ipv4_addr, parse_ipv4_addr, be_u16, be_u16, be_u32, be_u32, be_u32,
					 be_u32, be_u16, be_u16, be_u8, be_u8, be_u8, be_u8, be_u16, be_u16, be_u8, be_u8, be_u16))(input)?;

		Ok((res, NetflowDatagramV5Record { src_ip, dst_ip, next_hop_ip, snmp_in_if_idx, snmp_out_if_idx, flow_packets, flow_octets,
			start_sys_uptime, end_sys_uptime, src_port, dst_port, _pad0, tcp_flags, ip_protocol, ip_tos, src_asn, dst_asn, src_mask, dst_mask, _pad1 }))
	}
}

#[derive(Debug, Clone)]
pub struct NetflowDatagramV5 {
	pub sys_uptime_ms: u32,
	pub unix_sec: u32,
	pub unix_nsec: u32,
	pub flow_seqnum: u32,
	pub engine_type: u8,
	pub engine_id: u8,
	pub sampling_interval: u16,
	pub flow_records: Vec<NetflowDatagramV5Record>,
}

impl NetflowDatagramV5 {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], NetflowDatagramV5> {
		let (res, (num_records, sys_uptime_ms, unix_sec, unix_nsec, flow_seqnum, engine_type, engine_id, sampling_interval)) =
			tuple((be_u16, be_u32, be_u32, be_u32, be_u32, be_u8, be_u8, be_u16))(input)?;

		let (res, flow_records) = count(NetflowDatagramV5Record::parse_from_datagram, num_records as usize)(res)?;

		Ok((res, NetflowDatagramV5 { sys_uptime_ms, unix_sec, unix_nsec, flow_seqnum, engine_type, engine_id, sampling_interval, flow_records }))
	}
}