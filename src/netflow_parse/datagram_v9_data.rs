use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use nom::bytes::complete::take;
use nom::combinator::fail;
use nom::IResult;
use nom::number::complete::{be_u128, be_u16, be_u24, be_u32, be_u64, be_u8};
use crate::netflow_parse::datagram_v9_template::{NETFLOW_V9_OPTIONS_TEMPLATES, NETFLOW_V9_TEMPLATES, NetflowDatagramTemplateField};
use crate::netflow_parse::netflow_v9_typemap::NetflowV9TypeHandlingMode;

type Mac = String;

#[derive(Debug, Clone)]
pub enum NetflowV9DataValue {
	Number(u64),
	NonstandardNumber(Vec<u8>),
	IPv4(Ipv4Addr),
	IPv6(Ipv6Addr),
	MAC(Mac),
	String(String),
	Unknown(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct NetflowV9DataField {
	pub name: &'static str,
	pub value: NetflowV9DataValue,
}

impl NetflowV9DataField {
	pub fn parse_from_datagram<'a>(input: &'a [u8], type_info: &NetflowDatagramTemplateField) -> IResult<&'a [u8], NetflowV9DataField> {
		match type_info.field_type {
			None => {
				let (res, bytes) = take(type_info.field_length as usize)(input)?;
				Ok((res, NetflowV9DataField { name: "UNKNOWN", value: NetflowV9DataValue::Unknown(Vec::from(bytes)) }))
			}
			Some(ft) => {
				match ft.2 {
					NetflowV9TypeHandlingMode::Number => {
						match type_info.field_length {
							1 => {
								let (res, numval) = be_u8(input)?;
								Ok((res, NetflowV9DataField { name: ft.0, value: NetflowV9DataValue::Number(numval as u64) }))
							}
							2 => {
								let (res, numval) = be_u16(input)?;
								Ok((res, NetflowV9DataField { name: ft.0, value: NetflowV9DataValue::Number(numval as u64) }))
							}
							3 => {
								let (res, numval) = be_u24(input)?;
								Ok((res, NetflowV9DataField { name: ft.0, value: NetflowV9DataValue::Number(numval as u64) }))
							}
							4 => {
								let (res, numval) = be_u32(input)?;
								Ok((res, NetflowV9DataField { name: ft.0, value: NetflowV9DataValue::Number(numval as u64) }))
							}
							8 => {
								let (res, numval) = be_u64(input)?;
								Ok((res, NetflowV9DataField { name: ft.0, value: NetflowV9DataValue::Number(numval as u64) }))
							}
							_ => {
								let (res, numval) = take(type_info.field_length as usize)(input)?;
								Ok((res, NetflowV9DataField { name: ft.0, value: NetflowV9DataValue::NonstandardNumber(Vec::from(numval)) }))
							}
						}
					}
					NetflowV9TypeHandlingMode::IPv4 => {
						let (res, ipint) = be_u32(input)?;

						Ok((res, NetflowV9DataField { name: ft.0, value: NetflowV9DataValue::IPv4(Ipv4Addr::from(ipint)) }))
					}
					NetflowV9TypeHandlingMode::IPv6 => {
						let (res, ipint) = be_u128(input)?;

						Ok((res, NetflowV9DataField { name: ft.0, value: NetflowV9DataValue::IPv6(Ipv6Addr::from(ipint)) }))
					}
					NetflowV9TypeHandlingMode::MAC => {
						let (res, macbytes) = take(6usize)(input)?;
						let macstr = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
											 macbytes[0], macbytes[1], macbytes[2], macbytes[3], macbytes[4], macbytes[5]);

						Ok((res, NetflowV9DataField { name: ft.0, value: NetflowV9DataValue::MAC(macstr) }))
					}
					NetflowV9TypeHandlingMode::String => {
						let (res, rawstr) = take(type_info.field_length as usize)(input)?;

						Ok((res, NetflowV9DataField {
							name: ft.0,
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

#[derive(Debug, Clone)]
pub struct NetflowDatagramDataFlowSet {
	pub length: u16,
	pub records: Option<Vec<Vec<NetflowV9DataField>>>,
	pub option_records: Option<Vec<Vec<NetflowV9DataField>>>,
}

impl NetflowDatagramDataFlowSet {
	pub fn parse_from_datagram<'a>(input: &'a [u8], addr: &SocketAddr, template_id: u16) -> IResult<&'a [u8], NetflowDatagramDataFlowSet> {
		let (res, length) = be_u16(input)?;

		if let Some(ts) = NETFLOW_V9_TEMPLATES.lock().unwrap().get(&(*addr, template_id)) {
			let template_length = ts.total_field_length();

			let elem_count = (length - 4) / template_length;

			let mut curpos = res;

			let mut records: Vec<Vec<NetflowV9DataField>> = vec![];
			for _ in 0..elem_count {
				let mut fields: Vec<NetflowV9DataField> = vec![];
				for field_def in &ts.fields {
					let (res1, field) = NetflowV9DataField::parse_from_datagram(curpos, field_def)?;
					curpos = res1;

					fields.push(field);
				}
				records.push(fields);
			}

			let padding = (length - template_length * elem_count) - 4;

			let (res, _) = take(padding)(curpos)?;

			Ok((res, NetflowDatagramDataFlowSet { length, records: Some(records), option_records: None }))
		} else if let Some(ts) = NETFLOW_V9_OPTIONS_TEMPLATES.lock().unwrap().get(&(*addr, template_id)) {
			let template_length = ts.total_field_length();

			let elem_count = (length - 4) / template_length;

			let mut curpos = res;

			let mut records: Vec<Vec<NetflowV9DataField>> = vec![];
			for _ in 0..elem_count {
				let mut fields: Vec<NetflowV9DataField> = vec![];
				for field_def in &ts.option_fields {
					let (res1, field) = NetflowV9DataField::parse_from_datagram(curpos, field_def)?;
					curpos = res1;

					fields.push(field);
				}
				records.push(fields);
			}

			let padding = (length - template_length * elem_count) - 4;

			let (res, _) = take(padding)(curpos)?;

			Ok((res, NetflowDatagramDataFlowSet { length, records: None, option_records: Some(records) }))
		} else {
			fail(res)
		}
	}
}