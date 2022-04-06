//! Module dealing with parsing NetFlow data

use std::collections::HashMap;
use std::net::SocketAddr;
use nom::IResult;
use crate::netflow_parse::datagram::{NetflowDatagramData, NetflowPeekResult};
use crate::netflow_parse::datagram_v9_template::{NetflowDatagramOptionsTemplate, NetflowDatagramOptionsTemplateSet, NetflowDatagramTemplate, NetflowDatagramTemplateSet};

pub mod datagram;
pub mod datagram_v1;
pub mod datagram_v5;
pub mod datagram_v9;
pub mod datagram_ipfix;
pub mod netflow_v9_typemap;
pub mod datagram_v9_template;
pub mod datagram_v9_data;


/// Main NetFlow parser handling parsing, state, and providing an interface for it. It serves as the main entry point into the library
#[derive(Debug, Clone, Default)]
pub struct NetflowParser {
	templates: HashMap<(SocketAddr, u16), NetflowDatagramTemplate>,
	options_templates: HashMap<(SocketAddr, u16), NetflowDatagramOptionsTemplate>,
}

impl NetflowParser {
	/// Initialize parser state
	pub fn new() -> Self {
		Self::default()
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
	pub fn parse<'a>(&mut self, input: &'a [u8], addr: &SocketAddr) -> IResult<&'a [u8], NetflowDatagramData> {
		datagram::parse_netflow_data(input, addr, self)
	}

	/// Parse the initial non-data meta parts of NetFlow datagrams, returning the original array slice
	///
	/// This function can be used to handle UDP packets that arrive in the wrong order by matching the sequence number and caching packets
	pub fn peek_netflow_basic_info(input: &[u8]) -> IResult<&[u8], NetflowPeekResult> {
		datagram::peek_netflow_basic_info(input)
	}

	/// Manually register a new NetFlow template
	pub fn register_netflow_template(&mut self, set: &NetflowDatagramTemplateSet, addr: &SocketAddr) {
		for s in 0..set.template_ids.len() {
			let s = NetflowDatagramTemplate{template_id: *set.template_ids.get(s).unwrap(),
				field_count: *set.field_counts.get(s).unwrap(),
				fields: set.fields_vec.get(s).unwrap().clone()
			};
			self.templates.insert((*addr, s.template_id), s);
		}
	}

	/// Manually register a new NetFlow options template
	pub fn register_netflow_options_template(&mut self, set: &NetflowDatagramOptionsTemplateSet, addr: &SocketAddr) {
		// FIXME:
		for s in 0..set.template_ids.len() {
			let s = NetflowDatagramOptionsTemplate{template_id: *set.template_ids.get(s).unwrap(),
				option_field_count: *set.option_fields_lengths.get(s).unwrap() / 4,
				scope_field_count: *set.scope_fields_lengths.get(s).unwrap() / 4,
				scope_fields: set.scope_fields_vec.get(s).unwrap().clone(),
				option_fields: set.option_fields_vec.get(s).unwrap().clone()
			};
			self.options_templates.insert((*addr, s.template_id), s);
		}
	}
}