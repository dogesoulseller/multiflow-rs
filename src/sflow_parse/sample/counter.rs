use nom::combinator::fail;
use nom::IResult;
use nom::multi::count;
use nom::number::complete::{be_u32, be_u64};
use nom::sequence::tuple;

// TODO: Direction, Status enum
#[derive(Debug, Clone, Copy)]
pub struct SFlowCounterDataGeneric {
	pub index: u32,
	pub interface_type: u32,
	pub speed: u64,
	pub direction: u32,
	pub status: u32,
	pub in_octets: u64,
	pub in_ucast_packets: u32,
	pub in_multicast_packets: u32,
	pub in_broadcast_packets: u32,
	pub in_discarded: u32,
	pub in_errors: u32,
	pub in_unknown_protos: u32,
	pub out_octets: u64,
	pub out_ucast_packets: u32,
	pub out_multicast_packets: u32,
	pub out_broadcast_packets: u32,
	pub out_discarded: u32,
	pub out_errors: u32,
	pub out_promiscuous: u32,
}

impl SFlowCounterDataGeneric {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], SFlowCounterDataGeneric> {
		let (res, (index, interface_type, speed, direction, status, in_octets, in_ucast_packets,
			in_multicast_packets, in_broadcast_packets, in_discarded, in_errors,
			in_unknown_protos, out_octets, out_ucast_packets, out_multicast_packets,
			out_broadcast_packets, out_discarded, out_errors, out_promiscuous))
			= tuple((be_u32, be_u32, be_u64, be_u32, be_u32, be_u64, be_u32, be_u32, be_u32,
					 be_u32, be_u32, be_u32, be_u64, be_u32, be_u32, be_u32, be_u32, be_u32,
					 be_u32))(input)?;

		Ok((res, SFlowCounterDataGeneric {
			index,
			interface_type,
			speed,
			direction,
			status,
			in_octets,
			in_ucast_packets,
			in_multicast_packets,
			in_broadcast_packets,
			in_discarded,
			in_errors,
			in_unknown_protos,
			out_octets,
			out_ucast_packets,
			out_multicast_packets,
			out_broadcast_packets,
			out_discarded,
			out_errors,
			out_promiscuous,
		}))
	}
}


#[derive(Debug, Clone, Copy)]
pub struct SFlowCounterDataEthernet {
	pub alignment_errors: u32,
	pub fcs_errors: u32,
	pub single_collision_frames: u32,
	pub multiple_collision_frames: u32,
	pub sqe_test_errors: u32,
	pub deferred_transmissions: u32,
	pub late_collisions: u32,
	pub excessive_collisions: u32,
	pub internal_mac_transmit_errors: u32,
	pub carrier_sense_errors: u32,
	pub frame_too_longs: u32,
	pub internal_mac_receive_errors: u32,
	pub symbol_errors: u32,
}

impl SFlowCounterDataEthernet {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], SFlowCounterDataEthernet> {
		let (res, (alignment_errors, fcs_errors, single_collision_frames,
			multiple_collision_frames, sqe_test_errors, deferred_transmissions, late_collisions,
			excessive_collisions, internal_mac_transmit_errors, carrier_sense_errors,
			frame_too_longs, internal_mac_receive_errors, symbol_errors))
			= tuple((be_u32, be_u32, be_u32, be_u32, be_u32, be_u32, be_u32, be_u32, be_u32,
					 be_u32, be_u32, be_u32, be_u32))(input)?;

		Ok((res, SFlowCounterDataEthernet {
			alignment_errors,
			fcs_errors,
			single_collision_frames,
			multiple_collision_frames,
			sqe_test_errors,
			deferred_transmissions,
			late_collisions,
			excessive_collisions,
			internal_mac_transmit_errors,
			carrier_sense_errors,
			frame_too_longs,
			internal_mac_receive_errors,
			symbol_errors,
		}))
	}
}


#[derive(Debug, Clone, Copy)]
pub struct SFlowCounterDataTokenRing {
	pub line_errors: u32,
	pub burst_errors: u32,
	pub ac_errors: u32,
	pub abort_trans_errors: u32,
	pub internal_errors: u32,
	pub lost_frame_errors: u32,
	pub receive_congestions: u32,
	pub frame_copied_errors: u32,
	pub token_errors: u32,
	pub soft_errors: u32,
	pub hard_errors: u32,
	pub signal_loss: u32,
	pub transmit_beacons: u32,
	pub recoverys: u32,
	pub lobe_wires: u32,
	pub removes: u32,
	pub singles: u32,
	pub freq_errors: u32,
}

impl SFlowCounterDataTokenRing {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], SFlowCounterDataTokenRing> {
		let (res, (line_errors, burst_errors, ac_errors, abort_trans_errors, internal_errors,
			lost_frame_errors, receive_congestions, frame_copied_errors, token_errors, soft_errors,
			hard_errors, signal_loss, transmit_beacons, recoverys, lobe_wires, removes, singles, freq_errors))
			= tuple((be_u32, be_u32, be_u32, be_u32, be_u32, be_u32, be_u32, be_u32, be_u32,
					 be_u32, be_u32, be_u32, be_u32, be_u32, be_u32, be_u32, be_u32, be_u32))(input)?;

		Ok((res, SFlowCounterDataTokenRing {
			line_errors,
			burst_errors,
			ac_errors,
			abort_trans_errors,
			internal_errors,
			lost_frame_errors,
			receive_congestions,
			frame_copied_errors,
			token_errors,
			soft_errors,
			hard_errors,
			signal_loss,
			transmit_beacons,
			recoverys,
			lobe_wires,
			removes,
			singles,
			freq_errors,
		}))
	}
}

#[derive(Debug, Clone, Copy)]
pub struct SFlowCounterDataBaseVG {
	pub in_high_priority_frames: u32,
	pub in_high_priority_octets: u64,
	pub in_norm_priority_frames: u32,
	pub in_norm_priority_octets: u64,
	pub in_ipm_errors: u32,
	pub in_oversize_frame_errors: u32,
	pub in_data_errors: u32,
	pub in_null_addressed_frames: u32,
	pub out_high_priority_frames: u32,
	pub out_high_priority_octets: u64,
	pub transition_into_trainings: u32,
	pub hc_in_high_priority_octets: u64,
	pub hc_in_norm_priority_octets: u64,
	pub hc_out_high_priority_octets: u64,
}

impl SFlowCounterDataBaseVG {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], SFlowCounterDataBaseVG> {
		let (res, (in_high_priority_frames, in_high_priority_octets, in_norm_priority_frames,
			in_norm_priority_octets, in_ipm_errors, in_oversize_frame_errors, in_data_errors,
			in_null_addressed_frames, out_high_priority_frames, out_high_priority_octets,
			transition_into_trainings, hc_in_high_priority_octets, hc_in_norm_priority_octets, hc_out_high_priority_octets))
			= tuple((be_u32, be_u64, be_u32, be_u64, be_u32, be_u32, be_u32, be_u32, be_u32,
					 be_u64, be_u32, be_u64, be_u64, be_u64))(input)?;

		Ok((res, SFlowCounterDataBaseVG {
			in_high_priority_frames,
			in_high_priority_octets,
			in_norm_priority_frames,
			in_norm_priority_octets,
			in_ipm_errors,
			in_oversize_frame_errors,
			in_data_errors,
			in_null_addressed_frames,
			out_high_priority_frames,
			out_high_priority_octets,
			transition_into_trainings,
			hc_in_high_priority_octets,
			hc_in_norm_priority_octets,
			hc_out_high_priority_octets,
		}))
	}
}

#[derive(Debug, Clone, Copy)]
pub struct SFlowCounterDataVLAN {
	pub vlan_id: u32,
	pub octets: u64,
	pub ucast_packets: u32,
	pub multicast_packets: u32,
	pub broadcast_packets: u32,
	pub discards: u32,
}

impl SFlowCounterDataVLAN {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], SFlowCounterDataVLAN> {
		let (res, (vlan_id, octets, ucast_packets, multicast_packets, broadcast_packets, discards))
			= tuple((be_u32, be_u64, be_u32, be_u32, be_u32, be_u32))(input)?;

		Ok((res, SFlowCounterDataVLAN { vlan_id, octets, ucast_packets, multicast_packets, broadcast_packets, discards }))
	}
}

#[derive(Debug, Clone, Copy)]
pub struct SFlowCounterDataProcessor {
	pub cpu_percent_5s: u32,
	pub cpu_percent_1m: u32,
	pub cpu_percent_5m: u32,
	pub total_memory: u64,
	pub free_memory: u64,
}

impl SFlowCounterDataProcessor {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], SFlowCounterDataProcessor> {
		let (res, (cpu_percent_5s, cpu_percent_1m, cpu_percent_5m, total_memory, free_memory))
			= tuple((be_u32, be_u32, be_u32, be_u64, be_u64))(input)?;

		Ok((res, SFlowCounterDataProcessor { cpu_percent_5s, cpu_percent_1m, cpu_percent_5m, total_memory, free_memory }))
	}
}

#[derive(Debug, Clone, Copy)]
pub enum SFlowCounterRecord {
	Generic(SFlowCounterDataGeneric),
	Ethernet(SFlowCounterDataEthernet),
	TokenRing(SFlowCounterDataTokenRing),
	BaseVG(SFlowCounterDataBaseVG),
	VLAN(SFlowCounterDataVLAN),
	Processor(SFlowCounterDataProcessor),
}

impl SFlowCounterRecord {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], SFlowCounterRecord> {
		let (res, record_type) = be_u32(input)?;
		let (res, _record_size) = be_u32(res)?;

		// TODO: Handle unknown values
		match record_type {
			1 => {
				let (res, record) = SFlowCounterDataGeneric::parse_from_datagram(res)?;
				Ok((res, SFlowCounterRecord::Generic(record)))
			}
			2 => {
				let (res, record) = SFlowCounterDataEthernet::parse_from_datagram(res)?;
				Ok((res, SFlowCounterRecord::Ethernet(record)))
			}
			3 => {
				let (res, record) = SFlowCounterDataTokenRing::parse_from_datagram(res)?;
				Ok((res, SFlowCounterRecord::TokenRing(record)))
			}
			4 => {
				let (res, record) = SFlowCounterDataBaseVG::parse_from_datagram(res)?;
				Ok((res, SFlowCounterRecord::BaseVG(record)))
			}
			5 => {
				let (res, record) = SFlowCounterDataVLAN::parse_from_datagram(res)?;
				Ok((res, SFlowCounterRecord::VLAN(record)))
			}
			1001 => {
				let (res, record) = SFlowCounterDataProcessor::parse_from_datagram(res)?;
				Ok((res, SFlowCounterRecord::Processor(record)))
			}
			_ => {
				fail(res)
			}
		}
	}
}

#[derive(Debug, Clone)]
pub struct SFlowCounterSample {
	pub seq: u32,
	pub src: u32,
	pub records_count: u32,
	pub records: Vec<SFlowCounterRecord>,
}

impl SFlowCounterSample {
	pub fn parse_from_datagram(input: &[u8]) -> IResult<&[u8], SFlowCounterSample> {
		let (res, (seq, src, records_count)) = tuple((be_u32, be_u32, be_u32))(input)?;

		let (res, records) = count(SFlowCounterRecord::parse_from_datagram, records_count as usize)(res)?;

		Ok((res, SFlowCounterSample { seq, src, records_count, records }))
	}
}