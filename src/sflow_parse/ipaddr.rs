use nom::IResult;
use nom::number::complete::{be_u128, be_u32};

#[derive(Debug, Clone)]
pub enum DatagramIPAddr {
	IPv4(std::net::Ipv4Addr),
	IPv6(std::net::Ipv6Addr),
}

impl DatagramIPAddr {
	pub fn from_datagram_bytes(input: &[u8]) -> IResult<&[u8], Self> {
		let (input, ver) = be_u32(input)?;

		if ver == 1 { // IPv4
			let (res, v4) = be_u32(input)?;
			let ip = std::net::Ipv4Addr::from(v4);

			Ok((res, Self::IPv4(ip)))
		} else { // IPv6
			let (res, v6) = be_u128(input)?;
			let ip = std::net::Ipv6Addr::from(v6);

			Ok((res, Self::IPv6(ip)))
		}
	}
}
