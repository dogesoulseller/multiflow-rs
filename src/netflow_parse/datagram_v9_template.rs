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

/// Single template
#[derive(Debug, Clone)]
pub struct NetflowDatagramTemplate {
	pub template_id: u16,
	pub field_count: u16,
	pub fields: Vec<NetflowDatagramTemplateField>
}

impl NetflowDatagramTemplate {
	/// Get the total length of all template fields
	pub fn total_field_length(&self) -> u16 {
		let mut acc: u16 = 0;
		for f in &self.fields {
			acc += f.field_length;
		}

		acc
	}
}

/// Regular template set data
#[derive(Debug, Clone)]
pub struct NetflowDatagramTemplateSet {
	pub length: u16,
	pub template_ids: Vec<u16>,
	pub field_counts: Vec<u16>,
	pub fields_vec: Vec<Vec<NetflowDatagramTemplateField>>,
}

impl NetflowDatagramTemplateSet {
	pub(crate) fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, length) = be_u16(input)?;

		let mut template_ids: Vec<u16> = vec!();
		let mut field_counts: Vec<u16> = vec!();
		let mut fields_vec: Vec<Vec<NetflowDatagramTemplateField>> = vec!();

		let mut res_rem = res;
		let mut len_rem = length - 4;
		while len_rem != 0 {
			let (res, (template_id, field_count)) = tuple((be_u16, be_u16))(res_rem)?;

			let (res, fields) = count(NetflowDatagramTemplateField::parse_from_datagram, field_count as usize)(res)?;
			res_rem = res;
			len_rem -= field_count * 4 + 4;

			template_ids.push(template_id);
			field_counts.push(field_count);
			fields_vec.push(fields);
		}

		Ok((res_rem, Self { length, template_ids, field_counts, fields_vec }))
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

/// Single template
#[derive(Debug, Clone)]
pub struct NetflowDatagramOptionsTemplate {
	pub template_id: u16,
	pub scope_field_count: u16,
	pub option_field_count: u16,
	pub scope_fields: Vec<NetflowDatagramOptionsTemplateScopeField>,
	pub option_fields: Vec<NetflowDatagramTemplateField>
}

impl NetflowDatagramOptionsTemplate {
	/// Get the total length of all template fields
	pub fn total_field_length(&self) -> u16 {
		let mut acc: u16 = 0;

		for f in &self.option_fields {
			acc += f.field_length;
		}

		acc
	}
}

/// Options template set data
#[derive(Debug, Clone)]
pub struct NetflowDatagramOptionsTemplateSet {
	pub length: u16,
	pub template_ids: Vec<u16>,
	pub scope_fields_lengths: Vec<u16>,
	pub option_fields_lengths: Vec<u16>,
	pub scope_fields_vec: Vec<Vec<NetflowDatagramOptionsTemplateScopeField>>,
	pub option_fields_vec: Vec<Vec<NetflowDatagramTemplateField>>,
}

const INFO_LENGTH: u16 = 4;

impl NetflowDatagramOptionsTemplateSet {
	pub(crate) fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, length) = be_u16(input)?;

		let mut len_rem = length - 4;
		let mut res_rem = res;

		let mut template_ids: Vec<u16> = vec!();
		let mut scope_fields_lengths: Vec<u16> = vec!();
		let mut option_fields_lengths: Vec<u16> = vec!();
		let mut scope_fields_vec: Vec<Vec<NetflowDatagramOptionsTemplateScopeField>> = vec!();
		let mut option_fields_vec: Vec<Vec<NetflowDatagramTemplateField>> = vec!();

		while len_rem >= 4 {
			let (res, (template_id, scope_fields_length, option_fields_length)) = tuple((be_u16, be_u16, be_u16))(res_rem)?;

			len_rem -= 6;

			let scope_iter_count = scope_fields_length / INFO_LENGTH;
			let option_iter_count = option_fields_length / INFO_LENGTH;

			let (res, scope_fields)
				= count(NetflowDatagramOptionsTemplateScopeField::parse_from_datagram, scope_iter_count as usize)(res)?;

			let (res, option_fields)
				= count(NetflowDatagramTemplateField::parse_from_datagram, option_iter_count as usize)(res)?;

			res_rem = res;
			len_rem -= scope_fields_length + option_fields_length;

			template_ids.push(template_id);
			scope_fields_lengths.push(scope_fields_length);
			option_fields_lengths.push(option_fields_length);
			scope_fields_vec.push(scope_fields);
			option_fields_vec.push(option_fields);
		}

		Ok(((&res_rem[len_rem as usize..]), Self { length, template_ids, scope_fields_lengths, option_fields_lengths, scope_fields_vec, option_fields_vec }))
	}
}
