//! NetFlow IPFIX data field parsing

use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use nom::bytes::complete::take;
use nom::combinator::fail;
use nom::IResult;
use nom::number::complete::{be_u128, be_u16, be_u24, be_u32, be_u64, be_u8, be_i16, be_i24, be_i32, be_i64, be_i8, be_f32, be_f64};
use nom::sequence::tuple;
use crate::netflow_parse::datagram_ipfix_template::NetflowDatagramIPFIXTemplateField;
use crate::netflow_parse::netflow_ipfix_typemap::NetflowIPFIXTypeHandlingMode;
use crate::netflow_parse::NetflowParser;

/// Parsed data field's value with a given representation
#[derive(Debug, Clone)]
pub enum NetflowIPFIXDataValue {
	/// An unsigned number up to 8 bytes long (64-bit), made up of either a 1, 2, 3, 4, or 8 byte number. Other sizes are represented as `Unknown`
	Number(u64),
	/// A signed number up to 8 bytes long (64-bit), made up of either a 1, 2, 3, 4, or 8 byte number. Other sizes are represented as `Unknown`
	SignedNumber(i64),
	/// A single or double-precision floating point number represented as a double precision floating point number. Other sizes are represented as `Unknown`
	Float(f64),
	/// IPv4 address
	IPv4(Ipv4Addr),
	/// IPv6 address
	IPv6(Ipv6Addr),
	/// MAC address represented as a string in the format AA:BB:CC:DD:EE:FF
	MAC(String),
	/// An arbitrary UTF-8/ASCII string
	String(String),
	/// Unknown type, the bytes get stored raw
	Boolean(bool),
	DateTimeSeconds(u32),
	DateTimeMillis(u64),
	DateTimeMicros((u32, u32)),
	DateTimeNanos((u32, u32)),
	Unknown(Vec<u8>),
}

/// A single data field with a string name and a value
#[derive(Debug, Clone)]
pub struct NetflowIPFIXDataField {
	pub name: &'static str,
	pub type_id: u16,
	pub value: NetflowIPFIXDataValue,
}

impl NetflowIPFIXDataField {
	pub(crate) fn parse_from_datagram<'a>(input: &'a [u8], type_info: &NetflowDatagramIPFIXTemplateField) -> IResult<&'a [u8], Self> {
		// TODO: Proper variable length field parsing
		if type_info.field_length == 65535 {
			let (res, len_small) = be_u8(input)?;
			let resf: &[u8];
			let bytes_out: &[u8];

			if len_small != 255 {  // Small size
				let (_resf, _bytes) = take(len_small)(res)?;
				resf = _resf;
				bytes_out = _bytes;
			} else {  // Large size
				let (res, len_big) = be_u16(res)?;
				let (_resf, _bytes) = take(len_big)(res)?;

				resf = _resf;
				bytes_out = _bytes;
			}

			return match type_info.field_type {
				None => {
					Ok((resf, Self { name: "UNKNOWN", type_id: 0, value: NetflowIPFIXDataValue::Unknown(Vec::from(bytes_out)) }))
				}
				Some(ft) => {
					Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Unknown(Vec::from(bytes_out)) }))
				}
			}
		}

		match type_info.field_type {
			None => {
				let (res, bytes) = take(type_info.field_length as usize)(input)?;
				Ok((res, Self { name: "UNKNOWN", type_id: 0, value: NetflowIPFIXDataValue::Unknown(Vec::from(bytes)) }))
			}
			Some(ft) => {
				match ft.2 {
					NetflowIPFIXTypeHandlingMode::Number => {
						match type_info.field_length {
							1 => {
								let (res, numval) = be_u8(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Number(numval as u64) }))
							}
							2 => {
								let (res, numval) = be_u16(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Number(numval as u64) }))
							}
							3 => {
								let (res, numval) = be_u24(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Number(numval as u64) }))
							}
							4 => {
								let (res, numval) = be_u32(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Number(numval as u64) }))
							}
							8 => {
								let (res, numval) = be_u64(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Number(numval as u64) }))
							}
							_ => {
								let (res, numval) = take(type_info.field_length as usize)(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Unknown(Vec::from(numval)) }))
							}
						}
					}
					NetflowIPFIXTypeHandlingMode::IPv4 => {
						let (res, ipint) = be_u32(input)?;

						Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::IPv4(Ipv4Addr::from(ipint)) }))
					}
					NetflowIPFIXTypeHandlingMode::IPv6 => {
						let (res, ipint) = be_u128(input)?;

						Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::IPv6(Ipv6Addr::from(ipint)) }))
					}
					NetflowIPFIXTypeHandlingMode::MAC => {
						let (res, macbytes) = take(6usize)(input)?;
						let macstr = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
											 macbytes[0], macbytes[1], macbytes[2], macbytes[3], macbytes[4], macbytes[5]);

						Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::MAC(macstr) }))
					}
					NetflowIPFIXTypeHandlingMode::String => {
						let (res, rawstr) = take(type_info.field_length as usize)(input)?;

						Ok((res, Self {
							name: ft.0,
							type_id: ft.3,
							value: NetflowIPFIXDataValue::String(match String::from_utf8_lossy(rawstr) {
								Cow::Borrowed(s) => String::from(s),
								Cow::Owned(s) => s
							}),
						}))
					}
					NetflowIPFIXTypeHandlingMode::SignedNumber => {
						match type_info.field_length {
							1 => {
								let (res, numval) = be_i8(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::SignedNumber(numval as i64) }))
							}
							2 => {
								let (res, numval) = be_i16(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::SignedNumber(numval as i64) }))
							}
							3 => {
								let (res, numval) = be_i24(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::SignedNumber(numval as i64) }))
							}
							4 => {
								let (res, numval) = be_i32(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::SignedNumber(numval as i64) }))
							}
							8 => {
								let (res, numval) = be_i64(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::SignedNumber(numval as i64) }))
							}
							_ => {
								let (res, numval) = take(type_info.field_length as usize)(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Unknown(Vec::from(numval)) }))
							}
						}
					}
					NetflowIPFIXTypeHandlingMode::Float => {
						match type_info.field_length {
							4 => {
								let (res, numval) = be_f32(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Float(numval as f64) }))
							}
							8 => {
								let (res, numval) = be_f64(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Float(numval as f64) }))
							}
							_ => {
								let (res, numval) = take(type_info.field_length as usize)(input)?;
								Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Unknown(Vec::from(numval)) }))
							}
						}
					}
					NetflowIPFIXTypeHandlingMode::OctetArray => {
						let (res, numval) = take(type_info.field_length as usize)(input)?;
						Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Unknown(Vec::from(numval)) }))
					}
					NetflowIPFIXTypeHandlingMode::Boolean => {
						let (res, numval) = be_u8(input)?;
						Ok((res, Self { name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::Boolean(numval == 1) }))
					}
					NetflowIPFIXTypeHandlingMode::DateTimeSeconds => {
						let (res, val) = be_u32(input)?;

						Ok((res, Self {name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::DateTimeSeconds(val)}))
					}
					NetflowIPFIXTypeHandlingMode::DateTimeMillis => {
						let (res, val) = be_u64(input)?;

						Ok((res, Self {name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::DateTimeMillis(val)}))
					}
					NetflowIPFIXTypeHandlingMode::DateTimeMicros => {
						let (res, (secs, fraction)) = tuple((be_u32, be_u32))(input)?;

						Ok((res, Self {name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::DateTimeMicros((secs, fraction))}))
					}
					NetflowIPFIXTypeHandlingMode::DateTimeNanos => {
						let (res, (secs, fraction)) = tuple((be_u32, be_u32))(input)?;

						Ok((res, Self {name: ft.0, type_id: ft.3, value: NetflowIPFIXDataValue::DateTimeNanos((secs, fraction))}))
					}
				}
			}
		}
	}
}

/// Type of the records contained in a flow set
#[derive(Debug, Clone)]
pub enum NetflowDatagramIPFIXRecordsType {
	Regular(Vec<Vec<NetflowIPFIXDataField>>),
	Option(Vec<Vec<NetflowIPFIXDataField>>),
}

/// Source template type for a flow set
#[derive(Debug, Clone, Copy)]
pub enum NetflowDatagramIPFIXSourceTemplateType {
	Regular((SocketAddr, u16)),
	Option((SocketAddr, u16)),
}

/// A single flow set containing the records and fields
#[derive(Debug, Clone)]
pub struct NetflowDatagramIPFIXDataFlowSet {
	pub length: u16,
	pub source_template: NetflowDatagramIPFIXSourceTemplateType,
	pub records: NetflowDatagramIPFIXRecordsType,
}

impl NetflowDatagramIPFIXDataFlowSet {
	pub(crate) fn parse_from_datagram<'a>(input: &'a [u8], addr: &SocketAddr, template_id: u16, parser: &mut NetflowParser) -> IResult<&'a [u8], Self> {
		let (res, length) = be_u16(input)?;

		if let Some(ts) = parser.templates_ipfix.get(&(*addr, template_id)) {
			let template_length = ts.total_field_length();

			let elem_count = (length - 4) / template_length;

			let mut curpos = res;

			let mut records: Vec<Vec<NetflowIPFIXDataField>> = Vec::with_capacity(elem_count as usize);
			for _ in 0..elem_count {
				let mut fields: Vec<NetflowIPFIXDataField> = Vec::with_capacity(ts.fields.len());
				for field_def in &ts.fields {
					let (res1, field) = NetflowIPFIXDataField::parse_from_datagram(curpos, field_def)?;
					curpos = res1;

					fields.push(field);
				}
				records.push(fields);
			}

			Ok((&curpos[((length - template_length * elem_count) - 4) as usize..], Self {
				length,
				source_template: NetflowDatagramIPFIXSourceTemplateType::Regular((*addr, template_id)),
				records: NetflowDatagramIPFIXRecordsType::Regular(records),
			}))
		} else if let Some(ts) = parser.options_templates_ipfix.get(&(*addr, template_id)) {
			let template_length = ts.total_field_length();

			let elem_count = (length - 4) / template_length;

			let mut curpos = res;

			let mut records: Vec<Vec<NetflowIPFIXDataField>> = Vec::with_capacity(elem_count as usize);
			for _ in 0..elem_count {
				let mut fields: Vec<NetflowIPFIXDataField> = Vec::with_capacity(ts.option_fields.len());
				for field_def in &ts.option_fields {
					let (res1, field) = NetflowIPFIXDataField::parse_from_datagram(curpos, field_def)?;
					curpos = res1;

					fields.push(field);
				}
				records.push(fields);
			}

			Ok((&curpos[((length - template_length * elem_count) - 4) as usize..], Self {
				length,
				records: NetflowDatagramIPFIXRecordsType::Option(records),
				source_template: NetflowDatagramIPFIXSourceTemplateType::Option((*addr, template_id)),
			}))
		} else {
			eprintln!("Could not find template with ID {} for address {}", template_id, addr);
			fail(res)
		}
	}
}