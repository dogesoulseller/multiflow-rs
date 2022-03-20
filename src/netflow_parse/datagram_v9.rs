use std::net::SocketAddr;
use nom::combinator::fail;
use nom::IResult;
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::tuple;
use crate::netflow_parse::datagram_v9_data::NetflowDatagramDataFlowSet;
use crate::netflow_parse::datagram_v9_template::{NetflowDatagramOptionsTemplateSet, NetflowDatagramTemplateSet, register_netflow_options_template, register_netflow_template};

#[derive(Debug, Clone)]
pub enum NetflowDatagramV9FlowSet {
	Data(NetflowDatagramDataFlowSet),
	Template(NetflowDatagramTemplateSet),
	TemplateOption(NetflowDatagramOptionsTemplateSet),
}


impl NetflowDatagramV9FlowSet {
	pub fn parse_from_datagram<'a>(input: &'a [u8], socket: &SocketAddr) -> IResult<&'a [u8], NetflowDatagramV9FlowSet> {
		let (res, set_id) = be_u16(input)?;

		match set_id {
			0 => {
				let (res, parsed) = NetflowDatagramTemplateSet::parse_from_datagram(res)?;
				register_netflow_template(&parsed, socket);

				Ok((res, NetflowDatagramV9FlowSet::Template(parsed)))
			}
			1 => {
				let (res, parsed) = NetflowDatagramOptionsTemplateSet::parse_from_datagram(res)?;
				register_netflow_options_template(&parsed, socket);

				Ok((res, NetflowDatagramV9FlowSet::TemplateOption(parsed)))
			}
			2..=255 => {
				eprintln!("Got set id {}. This is an invalid set", set_id);
				fail(res)
			}
			256..=u16::MAX => {
				let (res, parsed) = NetflowDatagramDataFlowSet::parse_from_datagram(res, socket, set_id)?;

				Ok((res, NetflowDatagramV9FlowSet::Data(parsed)))
			}
		}
	}
}


#[derive(Debug, Clone)]
pub struct NetflowDatagramV9 {
	pub sys_uptime_ms: u32,
	pub unix_sec: u32,
	pub package_sequence: u32,
	pub source_id: u32,
	pub flow_records: Vec<NetflowDatagramV9FlowSet>,
}

impl NetflowDatagramV9 {
	pub fn parse_from_datagram<'a>(input: &'a [u8], addr: &SocketAddr) -> IResult<&'a [u8], NetflowDatagramV9> {
		let (res, (_num_records, sys_uptime_ms, unix_sec, package_sequence, source_id)) =
			tuple((be_u16, be_u32, be_u32, be_u32, be_u32))(input)?;

		let mut flow_records: Vec<NetflowDatagramV9FlowSet> = vec![];
		let mut curres = res;
		while !curres.is_empty() {
			let (res1, set) = NetflowDatagramV9FlowSet::parse_from_datagram(curres, addr)?;
			curres = res1;
			flow_records.push(set);
		}

		Ok((res, NetflowDatagramV9 { sys_uptime_ms, unix_sec, package_sequence, source_id, flow_records }))
	}
}