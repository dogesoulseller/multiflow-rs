//! NetFlow IPFIX template mappings and types

use nom::IResult;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::tuple;
use crate::netflow_parse::netflow_ipfix_typemap::{NETFLOW_IPFIX_DATATYPES, NetflowIPFIXScopeType, NetflowIPFIXTypeInfo};

/// Data field specification from template
#[derive(Debug, Clone, Copy)]
pub struct NetflowDatagramIPFIXTemplateField {
	pub field_type: Option<NetflowIPFIXTypeInfo>,
	pub field_length: u16,
	pub field_enterprise_id: Option<u32>
}

impl NetflowDatagramIPFIXTemplateField {
	pub(crate) fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (field_type_num, field_length)): (&[u8], (u16, u16)) = tuple((be_u16, be_u16))(input)?;

		if field_type_num & 0b1000_0000_0000_0000 != 0 {
			let (res, field_enterprise_id) = be_u32(res)?;
			Ok((res, Self { field_type: None, field_length, field_enterprise_id: Some(field_enterprise_id) }))
		} else {
			let field_type = NETFLOW_IPFIX_DATATYPES.get(&field_type_num)
				.map(|(s0, s1, hm, ft)| (*s0, *s1, *hm, *ft));

			Ok((res, Self { field_type, field_length, field_enterprise_id: None }))
		}
	}
}

/// Regular template set data
#[derive(Debug, Clone)]
pub struct NetflowDatagramIPFIXTemplateSet {
	pub length: u16,
	pub template_id: u16,
	pub field_count: u16,
	pub fields: Vec<NetflowDatagramIPFIXTemplateField>,
}

impl NetflowDatagramIPFIXTemplateSet {
	pub(crate) fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (length, template_id, field_count)) = tuple((be_u16, be_u16, be_u16))(input)?;

		let (res, fields) = count(NetflowDatagramIPFIXTemplateField::parse_from_datagram, field_count as usize)(res)?;
		Ok((res, Self { length, template_id, field_count, fields }))
	}

	/// Get the total length of all template fields
	pub fn total_field_length(&self) -> u16 {
		let mut acc: u16 = 0;
		for f in &self.fields {
			acc += f.field_length;
		}

		acc
	}
}

/// Data scope specification from template
#[derive(Debug, Clone, Copy)]
pub struct NetflowDatagramIPFIXOptionsTemplateScopeField {
	pub field_type: Option<NetflowIPFIXScopeType>,
	pub field_length: u16,
}

impl NetflowDatagramIPFIXOptionsTemplateScopeField {
	pub(crate) fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (field_type_num, field_length)) = tuple((be_u16, be_u16))(input)?;

		let field_type = NetflowIPFIXScopeType::try_from(field_type_num).ok();

		Ok((res, Self { field_type, field_length }))
	}
}

/// Options template set data
#[derive(Debug, Clone)]
pub struct NetflowDatagramIPFIXOptionsTemplateSet {
	pub length: u16,
	pub template_id: u16,
	pub scope_fields_length: u16,
	pub option_fields_length: u16,
	pub scope_fields: Vec<NetflowDatagramIPFIXOptionsTemplateScopeField>,
	pub option_fields: Vec<NetflowDatagramIPFIXTemplateField>,
}

const INFO_LENGTH: u16 = 4;

impl NetflowDatagramIPFIXOptionsTemplateSet {
	pub(crate) fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (length, template_id, scope_fields_length, option_fields_length)) = tuple((be_u16, be_u16, be_u16, be_u16))(input)?;

		let scope_iter_count = scope_fields_length / INFO_LENGTH;
		let option_iter_count = option_fields_length / INFO_LENGTH;

		let (res, scope_fields)
			= count(NetflowDatagramIPFIXOptionsTemplateScopeField::parse_from_datagram, scope_iter_count as usize)(res)?;

		let (res, option_fields)
			= count(NetflowDatagramIPFIXTemplateField::parse_from_datagram, option_iter_count as usize)(res)?;

		let padding_skip_n = length - (10 + scope_fields_length + option_fields_length);
		if padding_skip_n != 0 {
			Ok(((&res[padding_skip_n as usize..]), Self { length, template_id, scope_fields_length, option_fields_length, scope_fields, option_fields }))
		} else {
			Ok((res, Self { length, template_id, scope_fields_length, option_fields_length, scope_fields, option_fields }))
		}
	}

	/// Get the total length of all template fields
	pub fn total_field_length(&self) -> u16 {
		let mut acc: u16 = 0;

		for f in &self.option_fields {
			acc += f.field_length;
		}

		acc
	}
}
