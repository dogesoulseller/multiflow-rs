//! NetFlow v9 template mappings and types

use nom::IResult;
use nom::multi::count;
use nom::number::complete::be_u16;
use nom::sequence::tuple;
use crate::netflow_parse::netflow_v9_typemap::{NETFLOW_V9_DATATYPES, NetflowTypeInfo, NetflowV9ScopeType};

/// Data field specification from template
#[derive(Debug, Clone, Copy)]
pub struct NetflowDatagramTemplateField {
	pub field_type: Option<NetflowTypeInfo>,
	pub field_length: u16,
}

impl NetflowDatagramTemplateField {
	pub(crate) fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (field_type_num, field_length)) = tuple((be_u16, be_u16))(input)?;

		let field_type = NETFLOW_V9_DATATYPES.get(&field_type_num).map(|(s0, s1, hm, ft)| (*s0, *s1, *hm, *ft));

		Ok((res, Self { field_type, field_length }))
	}
}

/// Regular template set data
#[derive(Debug, Clone)]
pub struct NetflowDatagramTemplateSet {
	pub length: u16,
	pub template_id: u16,
	pub field_count: u16,
	pub fields: Vec<NetflowDatagramTemplateField>,
}

impl NetflowDatagramTemplateSet {
	pub(crate) fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (length, template_id, field_count)) = tuple((be_u16, be_u16, be_u16))(input)?;

		let (res, fields) = count(NetflowDatagramTemplateField::parse_from_datagram, field_count as usize)(res)?;
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
pub struct NetflowDatagramOptionsTemplateScopeField {
	pub field_type: Option<NetflowV9ScopeType>,
	pub field_length: u16,
}

impl NetflowDatagramOptionsTemplateScopeField {
	pub(crate) fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (field_type_num, field_length)) = tuple((be_u16, be_u16))(input)?;

		let field_type = NetflowV9ScopeType::try_from(field_type_num).ok();

		Ok((res, Self { field_type, field_length }))
	}
}

/// Options template set data
#[derive(Debug, Clone)]
pub struct NetflowDatagramOptionsTemplateSet {
	pub length: u16,
	pub template_id: u16,
	pub scope_fields_length: u16,
	pub option_fields_length: u16,
	pub scope_fields: Vec<NetflowDatagramOptionsTemplateScopeField>,
	pub option_fields: Vec<NetflowDatagramTemplateField>,
}

const INFO_LENGTH: u16 = 4;

impl NetflowDatagramOptionsTemplateSet {
	pub(crate) fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (length, template_id, scope_fields_length, option_fields_length)) = tuple((be_u16, be_u16, be_u16, be_u16))(input)?;

		let scope_iter_count = scope_fields_length / INFO_LENGTH;
		let option_iter_count = option_fields_length / INFO_LENGTH;

		let (res, scope_fields)
			= count(NetflowDatagramOptionsTemplateScopeField::parse_from_datagram, scope_iter_count as usize)(res)?;

		let (res, option_fields)
			= count(NetflowDatagramTemplateField::parse_from_datagram, option_iter_count as usize)(res)?;

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
