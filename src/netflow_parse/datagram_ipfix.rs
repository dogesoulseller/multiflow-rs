//! NetFlow v10/IPFIX parsing

use std::net::SocketAddr;
use nom::combinator::fail;
use nom::IResult;
use nom::multi::many_m_n;
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::tuple;
use crate::netflow_parse::datagram_ipfix_data::NetflowDatagramIPFIXDataFlowSet;
use crate::netflow_parse::datagram_ipfix_template::{NetflowDatagramIPFIXOptionsTemplateSet, NetflowDatagramIPFIXTemplateSet};
use crate::netflow_parse::NetflowParser;

/// Enum containing the three types of data sets in NetFlow IPFIX
#[derive(Debug, Clone)]
pub enum NetflowDatagramIPFIXFlowSet {
	/// The actual data contained in a packet, parsed using data from Template and TemplateOption fields from this or previous packets
	Data(NetflowDatagramIPFIXDataFlowSet),
	/// Data defining the flow data templates for this and future packets from this source
	Template(NetflowDatagramIPFIXTemplateSet),
	/// Data defining the metadata (options) templates for this and future packets from this source
	TemplateOption(NetflowDatagramIPFIXOptionsTemplateSet),
}

impl NetflowDatagramIPFIXFlowSet {
	pub(crate) fn parse_from_datagram<'a>(input: &'a [u8], socket: &SocketAddr, parser: &mut NetflowParser) -> IResult<&'a [u8], Self> {
		let (res, set_id) = be_u16(input)?;

		match set_id {
			2 => {
				let (res, parsed) = NetflowDatagramIPFIXTemplateSet::parse_from_datagram(res)?;
				parser.register_netflow_ipfix_template(&parsed, socket);

				Ok((res, Self::Template(parsed)))
			}
			3 => {
				let (res, parsed) = NetflowDatagramIPFIXOptionsTemplateSet::parse_from_datagram(res)?;
				parser.register_netflow_ipfix_options_template(&parsed, socket);

				Ok((res, Self::TemplateOption(parsed)))
			}
			0 | 1 | 4..=255 => {
				eprintln!("Got set id {}. This is an invalid set", set_id);
				fail(res)
			}
			256..=u16::MAX => {
				let (res, parsed) = NetflowDatagramIPFIXDataFlowSet::parse_from_datagram(res, socket, set_id, parser)?;

				Ok((res, Self::Data(parsed)))
			}
		}
	}
}


/// Full NetFlow IPFIX datagram data
#[derive(Debug, Clone)]
pub struct NetflowDatagramIPFIX {
	pub unix_sec: u32,
	pub package_sequence: u32,
	pub observation_domain_id: u32,
	pub flow_records: Vec<NetflowDatagramIPFIXFlowSet>,
}

impl NetflowDatagramIPFIX {
	// TODO: Template storage by observation domain id
	pub(crate) fn parse_from_datagram<'a>(input: &'a [u8], addr: &SocketAddr, parser: &mut NetflowParser) -> IResult<&'a [u8], Self> {
		let (res, (_len, unix_sec, package_sequence, observation_domain_id)) =
			tuple((be_u16, be_u32, be_u32, be_u32))(input)?;

		let (res, flow_records) = many_m_n(1, 30, |pd| { NetflowDatagramIPFIXFlowSet::parse_from_datagram(pd, addr, parser) })(res)?;

		Ok((res, Self { unix_sec, package_sequence, observation_domain_id, flow_records }))
	}
}