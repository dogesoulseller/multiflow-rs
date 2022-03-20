use multiflow::sflow_parse::datagram::parse_sflow_data;

fn main() {
	// Test setup for sFlow
	let mut recv_buf: [u8; 4096] = [0; 4096];
	let sock = std::net::UdpSocket::bind("0.0.0.0:6343").expect("Failed to bind to UDP socket");

	loop {
		let (byten, addr) = sock.recv_from(&mut recv_buf).expect("Failed to receive UDP data");

		let dg = parse_sflow_data(&recv_buf).unwrap().1;

		println!("Received {} bytes from {}\nDatagram: {:?}", byten, addr, dg);
	}
}