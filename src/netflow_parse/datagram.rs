use std::net::SocketAddr;
use nom::combinator::fail;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::IResult;
use nom::sequence::tuple;
use crate::netflow_parse::datagram_v1::NetflowDatagramV1;
use crate::netflow_parse::datagram_v5::NetflowDatagramV5;
use crate::netflow_parse::datagram_v9::NetflowDatagramV9;

/// Datagram enum for the various supported NetFlow versions
///
/// Each enum variant contains the version's respective datagram data
#[derive(Debug, Clone)]
pub enum NetflowDatagramData {
	DatagramV1(NetflowDatagramV1),
	DatagramV5(NetflowDatagramV5),
	DatagramV9(NetflowDatagramV9),
	IPFIX,
}


/// Data contained in the NetFlow v1 header
pub struct NetflowV1PeekData {
	pub flow_count: u16,
	pub sys_uptime: u32,
	pub unix_secs: u32,
	pub unix_nsecs: u32,
}

/// Data contained in the NetFlow v5 header
pub struct NetflowV5PeekData {
	pub flow_count: u16,
	pub sys_uptime: u32,
	pub unix_secs: u32,
	pub unix_nsecs: u32,
	pub total_flows: u32,
	pub engine_type: u8,
	pub engine_id: u8,
	pub sampling_interval: u16,
}

/// Data contained in the NetFlow v9 header
pub struct NetflowV9PeekData {
	pub flow_set_count: u16,
	pub sys_uptime: u32,
	pub unix_secs: u32,
	pub package_sequence_num: u32,
	pub source_id: u32,
}


/// Datagram peek enum for the various supported NetFlow versions
///
/// Each enum variant contains the version's respective header data
pub enum NetflowPeekResult {
	V1(NetflowV1PeekData),
	V5(NetflowV5PeekData),
	V9(NetflowV9PeekData),
	V10
}

/// Parse the initial non-data meta parts of NetFlow datagrams, returning the original array slice
///
/// This function can be used to handle UDP packets that arrive in the wrong order by matching the sequence number and caching results
pub fn peek_netflow_basic_info(input: &[u8]) -> IResult<&[u8], NetflowPeekResult> {
	let (res, netflow_version) = be_u16(input)?;

	match netflow_version {
		1 => {
			let (_, (flow_count, sys_uptime, unix_secs, unix_nsecs)) = tuple((be_u16, be_u32, be_u32, be_u32))(res)?;

			Ok((input, NetflowPeekResult::V1(NetflowV1PeekData{flow_count, sys_uptime, unix_secs, unix_nsecs})))
		},
		5 => {
			let (_, (flow_count, sys_uptime, unix_secs, unix_nsecs, total_flows, engine_type, engine_id, sampling_interval))
				= tuple((be_u16, be_u32, be_u32, be_u32, be_u32, be_u8, be_u8, be_u16))(res)?;

			Ok((input, NetflowPeekResult::V5(NetflowV5PeekData{flow_count, sys_uptime, unix_secs, unix_nsecs, total_flows,
				engine_type, engine_id, sampling_interval})))
		},
		9 => {
			let (_, (flow_set_count, sys_uptime, unix_secs, package_sequence_num, source_id))
				= tuple((be_u16, be_u32, be_u32, be_u32, be_u32))(res)?;

			Ok((input, NetflowPeekResult::V9(NetflowV9PeekData{flow_set_count, sys_uptime, unix_secs, package_sequence_num, source_id})))
		},
		_ => {
			eprintln!("Unsupported NetFlow version {}", netflow_version);
			fail(input)
		}
	}
}

/// Parse the netflow datagram bytes from `input` that are coming in from `addr`
///
/// The `addr` parameter is used for storing template information for NetFlow v9 and v10
/// Note that this function does not handle Ethernet, IP, or UDP/TCP/SCTP headers
///
/// # Errors
///
/// This function can fail in a few situations (list probably incomplete), returning a standard nom parser Fail error
/// - Unsupported NetFlow version
/// - Template with given ID has not been defined yet or has an ID between 2-255 (inclusive)
/// - The packet ends prematurely (due to the buffer being full)
pub fn parse_netflow_data<'a>(input: &'a [u8], addr: &SocketAddr) -> IResult<&'a [u8], NetflowDatagramData> {
	let (res, netflow_version) = be_u16(input)?;

	// TODO: IPFIX = 10
	match netflow_version {
		1 => {
			let (res, parsed) = NetflowDatagramV1::parse_from_datagram(res)?;
			Ok((res, NetflowDatagramData::DatagramV1(parsed)))
		}
		5 => {
			let (res, parsed) = NetflowDatagramV5::parse_from_datagram(res)?;
			Ok((res, NetflowDatagramData::DatagramV5(parsed)))
		}
		9 => {
			let (res, parsed) = NetflowDatagramV9::parse_from_datagram(res, addr)?;
			Ok((res, NetflowDatagramData::DatagramV9(parsed)))
		}
		// 10 => {
		// 	let (res, parsed) = NetflowDatagramIPFIX::parse_from_datagram(res)?;
		// 	Ok((res, NetflowDatagram{data: NetflowDatagramData::DatagramIPFIX(parsed)}))
		// }
		_ => {
			eprintln!("Unsupported NetFlow version {}", netflow_version);
			fail(res)
		}
	}
}