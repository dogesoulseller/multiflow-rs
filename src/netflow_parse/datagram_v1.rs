use std::net::Ipv4Addr;
use nom::IResult;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, be_u64, be_u8};
use nom::sequence::tuple;

/// Data record contained in a NetFlow v1 packet
#[derive(Debug, Clone, Copy)]
pub struct NetflowDatagramV1Record {
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
	pub ip_protocol: u8,
	pub ip_tos: u8,
	pub tcp_flags: u8,
	_pad1: u64,
}

fn parse_ipv4_addr(input: &[u8]) -> IResult<&[u8], Ipv4Addr> {
	let (res, ip_int) = be_u32(input)?;

	Ok((res, Ipv4Addr::from(ip_int)))
}

impl NetflowDatagramV1Record {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (src_ip, dst_ip, next_hop_ip, snmp_in_if_idx, snmp_out_if_idx, flow_packets,
			flow_octets, start_sys_uptime, end_sys_uptime, src_port, dst_port, _pad0, ip_protocol, ip_tos, tcp_flags, _pad1))
			= tuple((parse_ipv4_addr, parse_ipv4_addr, parse_ipv4_addr, be_u16, be_u16, be_u32, be_u32, be_u32,
					 be_u32, be_u16, be_u16, be_u8, be_u8, be_u8, be_u8, be_u64))(input)?;

		Ok((res, Self {
			src_ip,
			dst_ip,
			next_hop_ip,
			snmp_in_if_idx,
			snmp_out_if_idx,
			flow_packets,
			flow_octets,
			start_sys_uptime,
			end_sys_uptime,
			src_port,
			dst_port,
			_pad0,
			ip_protocol,
			ip_tos,
			tcp_flags,
			_pad1,
		}))
	}
}

/// Full NetFlow v1 datagram data
#[derive(Debug, Clone)]
pub struct NetflowDatagramV1 {
	pub sys_uptime_ms: u32,
	pub unix_sec: u32,
	pub unix_nsec: u32,
	pub flow_records: Vec<NetflowDatagramV1Record>,
}

impl NetflowDatagramV1 {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (num_records, sys_uptime_ms, unix_sec, unix_nsec)) =
			tuple((be_u16, be_u32, be_u32, be_u32))(input)?;

		let (res, flow_records) = count(NetflowDatagramV1Record::parse_from_datagram, num_records as usize)(res)?;

		Ok((res, Self { sys_uptime_ms, unix_sec, unix_nsec, flow_records }))
	}
}