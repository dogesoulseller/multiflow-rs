//! NetFlow v9 data field parsing

use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use nom::bytes::complete::take;
use nom::combinator::fail;
use nom::IResult;
use nom::number::complete::{be_u128, be_u16, be_u24, be_u32, be_u64, be_u8};
use crate::netflow_parse::datagram_v9_template::NetflowDatagramTemplateField;
use crate::netflow_parse::netflow_v9_typemap::NetflowV9TypeHandlingMode;
use crate::netflow_parse::NetflowParser;

/// Parsed data field's value with a given representation
#[derive(Debug, Clone)]
pub enum NetflowV9DataValue {
	/// A number up to 8 bytes long (64-bit), made up of either a 1, 2, 3, 4, or 8 byte number. Other numbers are represented as `Unknown`
	Number(u64),
	/// IPv4 address
	IPv4(Ipv4Addr),
	/// IPv6 address
	IPv6(Ipv6Addr),
	/// MAC address represented as a string in the format AA:BB:CC:DD:EE:FF
	MAC(String),
	/// An arbitrary UTF-8/ASCII string
	String(String),
	/// Unknown type, the bytes get stored raw
	Unknown(Vec<u8>),
}

/// A single data field with a string name and a value
#[derive(Debug, Clone)]
pub struct NetflowV9DataField {
	pub name: &'static str,
	pub type_id: u16,
	pub value: NetflowV9DataValue,
}

impl NetflowV9DataField {
	pub(crate) fn parse_from_datagram<'a>(input: &'a [u8], type_info: &NetflowDatagramTemplateField) -> IResult<&'a [u8], Self> {
		match type_info.field_type {
			None => {
				let (res, bytes) = take(type_info.field_length as usize)(input)?;
				Ok((res, Self { name: "UNKNOWN", type_id: 0, value: NetflowV9DataValue::Unknown(Vec::from(bytes)) }))
			}
			Some(ft) => {
				match ft.2 {
					NetflowV9TypeHandlingMode::Number => {
						match type_info.field_length {
							1 => {
								let (res, numval) = be_u8(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowV9DataValue::Number(numval as u64) }))
							}
							2 => {
								let (res, numval) = be_u16(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowV9DataValue::Number(numval as u64) }))
							}
							3 => {
								let (res, numval) = be_u24(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowV9DataValue::Number(numval as u64) }))
							}
							4 => {
								let (res, numval) = be_u32(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowV9DataValue::Number(numval as u64) }))
							}
							8 => {
								let (res, numval) = be_u64(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowV9DataValue::Number(numval as u64) }))
							}
							_ => {
								let (res, numval) = take(type_info.field_length as usize)(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowV9DataValue::Unknown(Vec::from(numval)) }))
							}
						}
					}
					NetflowV9TypeHandlingMode::IPv4 => {
						let (res, ipint) = be_u32(input)?;

						Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowV9DataValue::IPv4(Ipv4Addr::from(ipint)) }))
					}
					NetflowV9TypeHandlingMode::IPv6 => {
						let (res, ipint) = be_u128(input)?;

						Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowV9DataValue::IPv6(Ipv6Addr::from(ipint)) }))
					}
					NetflowV9TypeHandlingMode::MAC => {
						let (res, macbytes) = take(6usize)(input)?;
						let macstr = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
											 macbytes[0], macbytes[1], macbytes[2], macbytes[3], macbytes[4], macbytes[5]);

						Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowV9DataValue::MAC(macstr) }))
					}
					NetflowV9TypeHandlingMode::String => {
						let (res, rawstr) = take(type_info.field_length as usize)(input)?;

						Ok((res, Self {
							name: ft.0,
							type_id: ft.3,
							value: NetflowV9DataValue::String(match String::from_utf8_lossy(rawstr) {
								Cow::Borrowed(s) => String::from(s),
								Cow::Owned(s) => s
							}),
						}))
					}
				}
			}
		}
	}
}

/// Type of the records contained in a flow set
#[derive(Debug, Clone)]
pub enum NetflowDatagramRecordsType {
	Regular(Vec<Vec<NetflowV9DataField>>),
	Option(Vec<Vec<NetflowV9DataField>>),
}

/// Source template type for a flow set
#[derive(Debug, Clone, Copy)]
pub enum NetflowDatagramSourceTemplateType {
	Regular((SocketAddr, u16)),
	Option((SocketAddr, u16)),
}

/// A single flow set containing the records and fields
#[derive(Debug, Clone)]
pub struct NetflowDatagramDataFlowSet {
	pub length: u16,
	pub source_template: NetflowDatagramSourceTemplateType,
	pub records: NetflowDatagramRecordsType,
}

impl NetflowDatagramDataFlowSet {
	pub(crate) fn parse_from_datagram<'a>(input: &'a [u8], addr: &SocketAddr, template_id: u16, parser: &mut NetflowParser) -> IResult<&'a [u8], Self> {
		let (res, length) = be_u16(input)?;

		if let Some(ts) = parser.templates.get(&(*addr, template_id)) {
			let template_length = ts.total_field_length();

			let elem_count = (length - 4) / template_length;

			let mut curpos = res;

			let mut records: Vec<Vec<NetflowV9DataField>> = Vec::with_capacity(elem_count as usize);
			for _ in 0..elem_count {
				let mut fields: Vec<NetflowV9DataField> = Vec::with_capacity(ts.fields.len());
				for field_def in &ts.fields {
					let (res1, field) = NetflowV9DataField::parse_from_datagram(curpos, field_def)?;
					curpos = res1;

					fields.push(field);
				}
				records.push(fields);
			}

			Ok((&curpos[((length - template_length * elem_count) - 4) as usize..], Self {
				length,
				source_template: NetflowDatagramSourceTemplateType::Regular((*addr, template_id)),
				records: NetflowDatagramRecordsType::Regular(records),
			}))
		} else if let Some(ts) = parser.options_templates.get(&(*addr, template_id)) {
			let template_length = ts.total_field_length();

			let elem_count = (length - 4) / template_length;

			let mut curpos = res;

			let mut records: Vec<Vec<NetflowV9DataField>> = Vec::with_capacity(elem_count as usize);
			for _ in 0..elem_count {
				let mut fields: Vec<NetflowV9DataField> = Vec::with_capacity(ts.option_fields.len());
				for field_def in &ts.option_fields {
					let (res1, field) = NetflowV9DataField::parse_from_datagram(curpos, field_def)?;
					curpos = res1;

					fields.push(field);
				}
				records.push(fields);
			}

			Ok((&curpos[((length - template_length * elem_count) - 4) as usize..], Self {
				length,
				records: NetflowDatagramRecordsType::Option(records),
				source_template: NetflowDatagramSourceTemplateType::Option((*addr, template_id)),
			}))
		} else {
			eprintln!("Could not find template with ID {} for address {}", template_id, addr);
			fail(res)
		}
	}
}