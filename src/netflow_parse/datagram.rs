use std::net::SocketAddr;
use nom::combinator::fail;
use nom::number::complete::{be_u16};
use nom::IResult;
use crate::netflow_parse::datagram_v1::NetflowDatagramV1;
use crate::netflow_parse::datagram_v5::NetflowDatagramV5;
use crate::netflow_parse::datagram_v9::NetflowDatagramV9;

#[derive(Debug, Clone)]
pub enum NetflowDatagramData {
	DatagramV1(NetflowDatagramV1),
	DatagramV5(NetflowDatagramV5),
	DatagramV9(NetflowDatagramV9),
	IPFIX,
}

#[derive(Debug, Clone)]
pub struct NetflowDatagram {
	pub data: NetflowDatagramData,
}

pub fn datagram_parse<'a>(input: &'a [u8], addr: &SocketAddr) -> IResult<&'a [u8], NetflowDatagram> {
	let (res, netflow_version) = be_u16(input)?;

	// TODO: IPFIX = 10
	match netflow_version {
		1 => {
			let (res, parsed) = NetflowDatagramV1::parse_from_datagram(res)?;
			Ok((res, NetflowDatagram { data: NetflowDatagramData::DatagramV1(parsed) }))
		}
		5 => {
			let (res, parsed) = NetflowDatagramV5::parse_from_datagram(res)?;
			Ok((res, NetflowDatagram { data: NetflowDatagramData::DatagramV5(parsed) }))
		}
		9 => {
			let (res, parsed) = NetflowDatagramV9::parse_from_datagram(res, addr)?;
			Ok((res, NetflowDatagram { data: NetflowDatagramData::DatagramV9(parsed) }))
		}
		// 10 => {
		// 	let (res, parsed) = NetflowDatagramIPFIX::parse_from_datagram(res)?;
		// 	Ok((res, NetflowDatagram{data: NetflowDatagramData::DatagramIPFIX(parsed)}))
		// }
		_ => {
			fail(res)
		}
	}
}