//! Main datagram parsing module

use nom::number::complete::{be_u128, be_u32};
use nom::IResult;
use nom::multi::count;
use nom::sequence::tuple;
use crate::sflow_parse::sample::SFlowSample;

/// Base sFlow datagram
#[derive(Debug, Clone)]
pub struct Datagram {
	pub sflow_version: u32,
	pub agent_addr: std::net::IpAddr,
	pub sub_agent_id: u32,
	pub seq_num: u32,
	pub uptime: u32,
	pub sample_record: Vec<SFlowSample>,
}

fn parse_ipv4_or_ipv6(input: &[u8]) -> IResult<&[u8], std::net::IpAddr> {
	let (input, ver) = be_u32(input)?;
	if ver == 1 { // IPv4
		let (res, v4) = be_u32(input)?;
		Ok((res, std::net::IpAddr::from(std::net::Ipv4Addr::from(v4))))
	} else { // IPv6
		let (res, v6) = be_u128(input)?;
		Ok((res, std::net::IpAddr::from(std::net::Ipv6Addr::from(v6))))
	}
}

/// Parse sFlow datagram. It serves as the main entry point into the library
///
/// Note that this function does not handle Ethernet, IP, or UDP headers
pub fn parse_sflow_data(input: &[u8]) -> IResult<&[u8], Datagram> {
	let (res, (sfl, ag, sai, sn, ut, sample_count)) =
		tuple((be_u32, parse_ipv4_or_ipv6, be_u32, be_u32, be_u32, be_u32))(input)?;

	let (res, samples) = count(SFlowSample::parse_from_datagram, sample_count as usize)(res)?;

	Ok((res, Datagram { sflow_version: sfl, agent_addr: ag, sub_agent_id: sai, seq_num: sn, uptime: ut, sample_record: samples }))
}