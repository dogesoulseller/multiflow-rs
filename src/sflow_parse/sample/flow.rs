use nom::bytes::complete::take;
use nom::combinator::fail;
use nom::IResult;
use nom::multi::count;
use nom::number::complete::be_u32;
use nom::sequence::tuple;

// TODO: Protocol enum
#[derive(Debug, Clone)]
pub struct SFlowFlowRawPacketHeader {
	pub protocol: u32,
	pub frame_length: u32,
	pub stripped: u32,
	pub header_size: u32,
	pub header: Vec<u8>,
}

impl SFlowFlowRawPacketHeader {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (protocol, frame_length, stripped, header_size)) =
			tuple((be_u32, be_u32, be_u32, be_u32))(input)?;

		let (res, header) = take(header_size)(res)?;

		Ok((res, Self { protocol, frame_length, stripped, header_size, header: Vec::from(header) }))
	}
}

#[derive(Debug, Clone)]
pub enum SFlowFlowSampleRecord {
	Raw(SFlowFlowRawPacketHeader),
	Ethernet,
	IPv4,
	IPv6,
	ExtendedSwitch,
	ExtendedRouter,
	ExtendedGateway,
	ExtendedUserData,
	ExtendedUrlData,
	ExtendedMPLSData,
	ExtendedNATData,
	ExtendedMPLSTunnel,
	ExtendedMPLSVC,
	ExtendedMPLSFEC,
	ExtendedMPLSLVPFEC,
	ExtendedVLANTunnel,
}

impl SFlowFlowSampleRecord {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, record_type) = be_u32(input)?;
		let (res, _record_size) = be_u32(res)?;

		// TODO: Handle unknown values
		match record_type {
			1 => {
				let (res, record) = SFlowFlowRawPacketHeader::parse_from_datagram(res)?;
				Ok((res, Self::Raw(record)))
			}
			// 2 => {
			// 	let (res, record) = SFlowCounterDataEthernet::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowCounterRecordEthernetEthernet(record)));
			// }
			// 3 => {
			// 	let (res, record) = SFlowCounterDataTokenRing::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowCounterRecordIPv4TokenRing(record)));
			// }
			// 4 => {
			// 	let (res, record) = SFlowCounterDataBaseVG::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowCounterRecordIPv6BaseVG(record)));
			// }
			// 1001 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedSwitch(record)));
			// },
			// 1002 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedRouter(record)));
			// },
			// 1003 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedGateway(record)));
			// },
			// 1004 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedUserData(record)));
			// },
			// 1005 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedUrlData(record)));
			// },
			// 1006 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedMPLSData(record)));
			// },
			// 1007 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedNATData(record)));
			// },
			// 1008 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedMPLSTunnel(record)));
			// },
			// 1009 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedMPLSVC(record)));
			// },
			// 1010 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedMPLSFEC(record)));
			// },
			// 1011 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedMPLSLVPFEC(record)));
			// },
			// 1012 => {
			// 	let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
			// 	return Ok((res, SFlowFlowSampleRecord::ExtendedVLANTunnel(record)));
			// },
			//
			_ => {
				fail(res)
			}
		}
	}
}


#[derive(Debug, Clone)]
pub struct SFlowFlowSample {
	pub seq: u32,
	pub src: u32,
	pub rate: u32,
	pub pool: u32,
	pub dropped: u32,
	pub input_if: u32,
	pub output_if: u32,
	pub record_count: u32,
	pub records: Vec<SFlowFlowSampleRecord>,
}

impl SFlowFlowSample {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], Self> {
		let (res, (seq, src, rate, pool, dropped, input_if, output_if, record_count)) =
			tuple((be_u32, be_u32, be_u32, be_u32, be_u32, be_u32, be_u32, be_u32))(input)?;

		let (res, records) = count(SFlowFlowSampleRecord::parse_from_datagram, record_count as usize)(res)?;

		Ok((res, Self { seq, src, rate, pool, dropped, input_if, output_if, record_count, records }))
	}
}