use multiflow::netflow_parse::NetflowParser;

fn main() {
	// // Test setup for netflow
	let mut parser: NetflowParser = NetflowParser::new();
	let mut recv_buf: [u8; 4096] = [0; 4096];
	let sock = std::net::UdpSocket::bind("0.0.0.0:9000").expect("Failed to bind to UDP socket");

	// let (byten, addr) = sock.recv_from(&mut recv_buf).expect("Failed to receive UDP data");
	//
	// let start = std::time::Instant::now();
	// let dg0  = parser.parse(&recv_buf[0..byten], &addr).unwrap().1;
	// let end = std::time::Instant::now();
	// eprintln!("Parsing took {} ns", (end.duration_since(start)).as_nanos());
	//
	// let (byten, addr) = sock.recv_from(&mut recv_buf).expect("Failed to receive UDP data");
	//
	// let start = std::time::Instant::now();
	// let dg1  = parser.parse(&recv_buf[0..byten], &addr).unwrap().1;
	// let end = std::time::Instant::now();
	// eprintln!("Parsing took {} ns", (end.duration_since(start)).as_nanos());
	//
	// let start = std::time::Instant::now();
	// let dg2  = parser.parse(&recv_buf[0..byten], &addr).unwrap().1;
	// let end = std::time::Instant::now();
	// eprintln!("Parsing took {} ns", (end.duration_since(start)).as_nanos());
	//
	// let start = std::time::Instant::now();
	// let dg3  = parser.parse(&recv_buf[0..byten], &addr).unwrap().1;
	// let end = std::time::Instant::now();
	// eprintln!("Parsing took {} ns", (end.duration_since(start)).as_nanos());

	loop {
		let (byten, addr) = sock.recv_from(&mut recv_buf).expect("Failed to receive UDP data");
		eprintln!("Received {} bytes from {}", byten, addr);

		let dg = match parser.parse(&recv_buf[0..byten], &addr) {
			Ok((_, dg)) => dg,
			Err(_e) => {
				eprintln!("Failed to process NetFlow packet");
				continue;
			}
		};

		eprintln!("Datagram: {:#?}", dg);
	}
}
