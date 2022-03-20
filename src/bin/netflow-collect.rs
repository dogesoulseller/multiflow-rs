use multiflow::netflow_parse;

fn main() {
	// Test setup for netflow
	let mut recv_buf: [u8; 4096] = [0; 4096];
	let sock = std::net::UdpSocket::bind("0.0.0.0:9000").expect("Failed to bind to UDP socket");

	loop {
		let (byten, addr) = sock.recv_from(&mut recv_buf).expect("Failed to receive UDP data");
		eprintln!("Received {} bytes from {}", byten, addr);

		let dg = netflow_parse::datagram::datagram_parse(&recv_buf[0..byten], &addr).unwrap().1;

		eprintln!("Datagram: {:#?}", dg);
	}
}
