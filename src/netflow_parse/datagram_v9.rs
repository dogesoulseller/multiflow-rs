//! NetFlow v9 parsing

use std::net::SocketAddr;
use nom::combinator::fail;
use nom::IResult;
use nom::multi::many_m_n;
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::tuple;
use crate::netflow_parse::datagram_v9_data::NetflowDatagramDataFlowSet;
use crate::netflow_parse::datagram_v9_template::{NetflowDatagramOptionsTemplateSet, NetflowDatagramTemplateSet};
use crate::netflow_parse::NetflowParser;

/// Enum containing the three types of data sets in NetFlow v9
#[derive(Debug, Clone)]
pub enum NetflowDatagramV9FlowSet {
	/// The actual data contained in a packet, parsed using data from Template and TemplateOption fields from this or previous packets
	Data(NetflowDatagramDataFlowSet),
	/// Data defining the flow data templates for this and future packets from this source
	Template(NetflowDatagramTemplateSet),
	/// Data defining the metadata (options) templates for this and future packets from this source
	TemplateOption(NetflowDatagramOptionsTemplateSet),
}

impl NetflowDatagramV9FlowSet {
	pub(crate) fn parse_from_datagram<'a>(input: &'a [u8], socket: &SocketAddr, parser: &mut NetflowParser) -> IResult<&'a [u8], Self> {
		let (res, set_id) = be_u16(input)?;

		match set_id {
			0 => {
				let (res, parsed) = NetflowDatagramTemplateSet::parse_from_datagram(res)?;
				parser.register_netflow_template(&parsed, socket);

				Ok((res, Self::Template(parsed)))
			}
			1 => {
				let (res, parsed) = NetflowDatagramOptionsTemplateSet::parse_from_datagram(res)?;
				parser.register_netflow_options_template(&parsed, socket);

				Ok((res, Self::TemplateOption(parsed)))
			}
			2..=255 => {
				eprintln!("Got set id {}. This is an invalid set", set_id);
				fail(res)
			}
			256..=u16::MAX => {
				let (res, parsed) = NetflowDatagramDataFlowSet::parse_from_datagram(res, socket, set_id, parser)?;

				Ok((res, Self::Data(parsed)))
			}
		}
	}
}


/// Full NetFlow v9 datagram data
#[derive(Debug, Clone)]
pub struct NetflowDatagramV9 {
	pub sys_uptime_ms: u32,
	pub unix_sec: u32,
	pub package_sequence: u32,
	pub source_id: u32,
	pub flow_records: Vec<NetflowDatagramV9FlowSet>,
}

impl NetflowDatagramV9 {
	pub(crate) fn parse_from_datagram<'a>(input: &'a [u8], addr: &SocketAddr, parser: &mut NetflowParser) -> IResult<&'a [u8], Self> {
		let (res, (_num_records, sys_uptime_ms, unix_sec, package_sequence, source_id)) =
			tuple((be_u16, be_u32, be_u32, be_u32, be_u32))(input)?;

		let (res, flow_records) = many_m_n(1, 30, |pd| { NetflowDatagramV9FlowSet::parse_from_datagram(pd, addr, parser) })(res)?;

		Ok((res, Self { sys_uptime_ms, unix_sec, package_sequence, source_id, flow_records }))
	}
}