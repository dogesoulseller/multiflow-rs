use nom::number::complete::{be_u32};
use nom::IResult;
use nom::multi::count;
use nom::sequence::tuple;
use crate::sflow_parse::ipaddr::DatagramIPAddr;
use crate::sflow_parse::sample::SFlowSample;

#[derive(Debug, Clone)]
pub struct Datagram {
	pub sflow_version: u32,
	pub agent_addr: DatagramIPAddr,
	pub sub_agent_id: u32,
	pub seq_num: u32,
	pub uptime: u32,
	pub sample_record: Vec<SFlowSample>,
}

pub fn parse_sflow_data(input: &[u8]) -> IResult<&[u8], Datagram> {
	let (res, (sfl, ag, sai, sn, ut, sample_count)) =
		tuple((be_u32, DatagramIPAddr::from_datagram_bytes, be_u32, be_u32, be_u32, be_u32))(input)?;

	let (res, samples) = count(SFlowSample::parse_from_datagram, sample_count as usize)(res)?;

	Ok((res, Datagram { sflow_version: sfl, agent_addr: ag, sub_agent_id: sai, seq_num: sn, uptime: ut, sample_record: samples }))
}