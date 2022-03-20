pub mod flow;
pub mod counter;

use nom::combinator::fail;
use nom::IResult;
use nom::number::complete::be_u32;
use crate::sflow_parse::sample::counter::SFlowCounterSample;
use crate::sflow_parse::sample::flow::SFlowFlowSample;

// TODO: Expanded
#[derive(Debug, Clone)]
pub enum SFlowSample {
	Flow(SFlowFlowSample),
	Counter(SFlowCounterSample),
	ExpFlow,
	ExpCounter,
}

impl SFlowSample {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], SFlowSample> {
		let (res, sample_type): (&[u8], u32) = be_u32(input)?;
		let (res, _sample_size): (&[u8], u32) = be_u32(res)?;

		// TODO: Handle unknown values
		return match sample_type {
			1 => {
				let (res, s) = SFlowFlowSample::parse_from_datagram(res)?;
				Ok((res, SFlowSample::Flow(s)))
			}
			2 => {
				let (res, s) = SFlowCounterSample::parse_from_datagram(res)?;
				Ok((res, SFlowSample::Counter(s)))
			}
			// 3 => ExpFlow,
			// 4 => ExpCounter,
			_ => { fail(res) }
		};
	}
}
