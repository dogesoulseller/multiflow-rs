use multiflow::sflow_parse::datagram::parse_sflow_data;

pub fn decode_hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
	(0..s.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&s[i..i + 2], 16))
		.collect()
}

fn main() {
	let mut ctr_sample_bytes: Vec<Vec<u8>> = vec![];
	let mut flw_sample_bytes: Vec<Vec<u8>> = vec![];

	for l in str::lines(include_str!("./res/test_counter_sample.txt")) {
		ctr_sample_bytes.push(decode_hex(l).unwrap());
	}

	for l in str::lines(include_str!("./res/test_flow_sample.txt")) {
		flw_sample_bytes.push(decode_hex(l).unwrap());
	}

	for x in ctr_sample_bytes {
		let test_dg = parse_sflow_data(x.as_slice()).unwrap().1;
		println!("Datagram counter: {:?}", test_dg);
	}

	println!();

	for x in flw_sample_bytes {
		let test_dg = parse_sflow_data(x.as_slice()).unwrap().1;
		println!("Datagram sample: {:?}", test_dg);
	}
}