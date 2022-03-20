#[derive(Debug, Clone, Copy)]
pub enum NetflowV9TypeHandlingMode {
	Number,
	IPv4,
	IPv6,
	MAC,
	String,
}

#[derive(Debug, Clone, Copy)]
pub enum NetflowV9ScopeType {
	System = 1,
	Interface = 2,
	LineCard = 3,
	NetFlowCache = 4,
	Template = 5,
}

impl TryFrom<u16> for NetflowV9ScopeType {
	type Error = ();

	fn try_from(v: u16) -> Result<Self, Self::Error> {
		match v {
			1 => Ok(NetflowV9ScopeType::System),
			2 => Ok(NetflowV9ScopeType::Interface),
			3 => Ok(NetflowV9ScopeType::LineCard),
			4 => Ok(NetflowV9ScopeType::NetFlowCache),
			5 => Ok(NetflowV9ScopeType::Template),
			_ => Err(())
		}
	}
}

lazy_static! {
	pub static ref NETFLOW_V9_DATATYPES: std::collections::HashMap<u16, (&'static str, &'static str, NetflowV9TypeHandlingMode)> = {
		let mut hm = std::collections::HashMap::new();
		hm.insert(1,  ("IN_BYTES", "Incoming counter with length N x 8 bits for number of bytes associated with an IP Flow.", NetflowV9TypeHandlingMode::Number));
		hm.insert(2,  ("IN_PKTS", "Incoming counter with length N x 8 bits for the number of packets associated with an IP Flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(3,  ("FLOWS", "Number of flows that were aggregated; default for N is 4", NetflowV9TypeHandlingMode::Number));
		hm.insert(4,  ("PROTOCOL", "IP protocol byte", NetflowV9TypeHandlingMode::Number));
		hm.insert(5,  ("SRC_TOS", "Type of Service byte setting when entering incoming interface", NetflowV9TypeHandlingMode::Number));
		hm.insert(6,  ("TCP_FLAGS", "Cumulative of all the TCP flags seen for this flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(7,  ("L4_SRC_PORT", "TCP/UDP source port number i.e.: FTP, Telnet, or equivalent", NetflowV9TypeHandlingMode::Number));
		hm.insert(8,  ("IPV4_SRC_ADDR", "IPv4 source address", NetflowV9TypeHandlingMode::IPv4));
		hm.insert(9,  ("SRC_MASK", "The number of contiguous bits in the source address subnet mask i.e.: the submask in slash notation", NetflowV9TypeHandlingMode::Number));
		hm.insert(10, ("INPUT_SNMP", "Input interface index; default for N is 2 but higher values could be used", NetflowV9TypeHandlingMode::Number));
		hm.insert(11, ("L4_DST_PORT", "TCP/UDP destination port number i.e.: FTP, Telnet, or equivalent", NetflowV9TypeHandlingMode::Number));
		hm.insert(12, ("IPV4_DST_ADDR", "IPv4 destination address", NetflowV9TypeHandlingMode::IPv4));
		hm.insert(13, ("DST_MASK", "The number of contiguous bits in the destination address subnet mask i.e.: the submask in slash notation", NetflowV9TypeHandlingMode::Number));
		hm.insert(14, ("OUTPUT_SNMP", "Output interface index; default for N is 2 but higher values could be used", NetflowV9TypeHandlingMode::Number));
		hm.insert(15, ("IPV4_NEXT_HOP", "IPv4 address of next-hop router", NetflowV9TypeHandlingMode::IPv4));
		hm.insert(16, ("SRC_AS", "Source BGP autonomous system number where N could be 2 or 4", NetflowV9TypeHandlingMode::Number));
		hm.insert(17, ("DST_AS", "Destination BGP autonomous system number where N could be 2 or 4", NetflowV9TypeHandlingMode::Number));
		hm.insert(18, ("BGP_IPV4_NEXT_HOP", "Next-hop router's IP in the BGP domain", NetflowV9TypeHandlingMode::IPv4));
		hm.insert(19, ("MUL_DST_PKTS", "IP multicast outgoing packet counter with length N x 8 bits for packets associated with the IP Flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(20, ("MUL_DST_BYTES", "IP multicast outgoing byte counter with length N x 8 bits for bytes associated with the IP Flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(21, ("LAST_SWITCHED", "System uptime at which the last packet of this flow was switched", NetflowV9TypeHandlingMode::Number));
		hm.insert(22, ("FIRST_SWITCHED", "System uptime at which the first packet of this flow was switched", NetflowV9TypeHandlingMode::Number));
		hm.insert(23, ("OUT_BYTES", "Outgoing counter with length N x 8 bits for the number of bytes associated with an IP Flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(24, ("OUT_PKTS", "Outgoing counter with length N x 8 bits for the number of packets associated with an IP Flow.", NetflowV9TypeHandlingMode::Number));
		hm.insert(25, ("MIN_PKT_LNGTH", "Minimum IP packet length on incoming packets of the flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(26, ("MAX_PKT_LNGTH", "Maximum IP packet length on incoming packets of the flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(27, ("IPV6_SRC_ADDR", "IPv6 Source Address", NetflowV9TypeHandlingMode::IPv6));
		hm.insert(28, ("IPV6_DST_ADDR", "IPv6 Destination Address", NetflowV9TypeHandlingMode::IPv6));
		hm.insert(29, ("IPV6_SRC_MASK", "Length of the IPv6 source mask in contiguous bits", NetflowV9TypeHandlingMode::Number));
		hm.insert(30, ("IPV6_DST_MASK", "Length of the IPv6 destination mask in contiguous bits", NetflowV9TypeHandlingMode::Number));
		hm.insert(31, ("IPV6_FLOW_LABEL", "IPv6 flow label as per RFC 2460 definition", NetflowV9TypeHandlingMode::Number));
		hm.insert(32, ("ICMP_TYPE", "Internet Control Message Protocol (ICMP) packet type; reported as ((ICMP Type*256) + ICMP code)", NetflowV9TypeHandlingMode::Number));
		hm.insert(33, ("MUL_IGMP_TYPE", "Internet Group Management Protocol (IGMP) packet type", NetflowV9TypeHandlingMode::Number));
		hm.insert(34, ("SAMPLING_INTERVAL", "When using sampled NetFlow, the rate at which packets are sampled i.e.: a value of 100 indicates that one of every 100 packets is sampled", NetflowV9TypeHandlingMode::Number));
		hm.insert(35, ("SAMPLING_ALGORITHM", "The type of algorithm used for sampled NetFlow: 0x01 Deterministic Sampling ,0x02 Random Sampling", NetflowV9TypeHandlingMode::Number));
		hm.insert(36, ("FLOW_ACTIVE_TIMEOUT", "Timeout value (in seconds) for active flow entries in the NetFlow cache", NetflowV9TypeHandlingMode::Number));
		hm.insert(37, ("FLOW_INACTIVE_TIMEOUT", "Timeout value (in seconds) for inactive flow entries in the NetFlow cache", NetflowV9TypeHandlingMode::Number));
		hm.insert(38, ("ENGINE_TYPE", "Type of flow switching engine: RP = 0, VIP/Linecard = 1", NetflowV9TypeHandlingMode::Number));
		hm.insert(39, ("ENGINE_ID", "ID number of the flow switching engine", NetflowV9TypeHandlingMode::Number));
		hm.insert(40, ("TOTAL_BYTES_EXP", "Counter with length N x 8 bits for bytes for the number of bytes exported by the Observation Domain", NetflowV9TypeHandlingMode::Number));
		hm.insert(41, ("TOTAL_PKTS_EXP", "Counter with length N x 8 bits for bytes for the number of packets exported by the Observation Domain", NetflowV9TypeHandlingMode::Number));
		hm.insert(42, ("TOTAL_FLOWS_EXP", "Counter with length N x 8 bits for bytes for the number of flows exported by the Observation Domain", NetflowV9TypeHandlingMode::Number));
		hm.insert(44, ("IPV4_SRC_PREFIX", "IPv4 source address prefix (specific for Catalyst architecture)", NetflowV9TypeHandlingMode::Number));
		hm.insert(45, ("IPV4_DST_PREFIX", "IPv4 destination address prefix (specific for Catalyst architecture)", NetflowV9TypeHandlingMode::Number));
		hm.insert(46, ("MPLS_TOP_LABEL_TYPE", "MPLS Top Label Type: 0x00 UNKNOWN 0x01 TE-MIDPT 0x02 ATOM 0x03 VPN 0x04 BGP 0x05 LDP", NetflowV9TypeHandlingMode::Number));
		hm.insert(47, ("MPLS_TOP_LABEL_IP_ADDR", "Forwarding Equivalent Class corresponding to the MPLS Top Label", NetflowV9TypeHandlingMode::Number));
		hm.insert(48, ("FLOW_SAMPLER_ID", "Identifier shown in 'show flow-sampler'", NetflowV9TypeHandlingMode::Number));
		hm.insert(49, ("FLOW_SAMPLER_MODE", "The type of algorithm used for sampling data: 0x02 random sampling. Use in connection with FLOW_SAMPLER_MODE", NetflowV9TypeHandlingMode::Number));
		hm.insert(50, ("FLOW_SAMPLER_RANDOM_INTERVAL", "Packet interval at which to sample. Use in connection with FLOW_SAMPLER_MODE", NetflowV9TypeHandlingMode::Number));
		hm.insert(52, ("MIN_TTL", "Minimum TTL on incoming packets of the flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(53, ("MAX_TTL", "Maximum TTL on incoming packets of the flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(54, ("IPV4_IDENT", "The IP v4 identification field", NetflowV9TypeHandlingMode::Number));
		hm.insert(55, ("DST_TOS", "Type of Service byte setting when exiting outgoing interface", NetflowV9TypeHandlingMode::Number));
		hm.insert(56, ("IN_SRC_MAC", "Incoming source MAC address", NetflowV9TypeHandlingMode::MAC));
		hm.insert(57, ("OUT_DST_MAC", "Outgoing destination MAC address", NetflowV9TypeHandlingMode::MAC));
		hm.insert(58, ("SRC_VLAN", "Virtual LAN identifier associated with ingress interface", NetflowV9TypeHandlingMode::Number));
		hm.insert(59, ("DST_VLAN", "Virtual LAN identifier associated with egress interface", NetflowV9TypeHandlingMode::Number));
		hm.insert(60, ("IP_PROTOCOL_VERSION", "Internet Protocol Version Set to 4 for IPv4, set to 6 for IPv6. If not present in the template, then version 4 is assumed.", NetflowV9TypeHandlingMode::Number));
		hm.insert(61, ("DIRECTION", "Flow direction: 0 - ingress flow, 1 - egress flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(62, ("IPV6_NEXT_HOP", "IPv6 address of the next-hop router", NetflowV9TypeHandlingMode::IPv6));
		hm.insert(63, ("BPG_IPV6_NEXT_HOP", "Next-hop router in the BGP domain", NetflowV9TypeHandlingMode::IPv6));
		hm.insert(64, ("IPV6_OPTION_HEADERS", "Bit-encoded field identifying IPv6 option headers found in the flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(70, ("MPLS_LABEL_1", "MPLS label at position 1 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowV9TypeHandlingMode::Number));
		hm.insert(71, ("MPLS_LABEL_2", "MPLS label at position 2 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowV9TypeHandlingMode::Number));
		hm.insert(72, ("MPLS_LABEL_3", "MPLS label at position 3 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowV9TypeHandlingMode::Number));
		hm.insert(73, ("MPLS_LABEL_4", "MPLS label at position 4 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowV9TypeHandlingMode::Number));
		hm.insert(74, ("MPLS_LABEL_5", "MPLS label at position 5 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowV9TypeHandlingMode::Number));
		hm.insert(75, ("MPLS_LABEL_6", "MPLS label at position 6 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowV9TypeHandlingMode::Number));
		hm.insert(76, ("MPLS_LABEL_7", "MPLS label at position 7 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowV9TypeHandlingMode::Number));
		hm.insert(77, ("MPLS_LABEL_8", "MPLS label at position 8 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowV9TypeHandlingMode::Number));
		hm.insert(78, ("MPLS_LABEL_9", "MPLS label at position 9 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowV9TypeHandlingMode::Number));
		hm.insert(79, ("MPLS_LABEL_10", "MPLS label at position 10 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowV9TypeHandlingMode::Number));
		hm.insert(80, ("IN_DST_MAC", "Incoming destination MAC address", NetflowV9TypeHandlingMode::MAC));
		hm.insert(81, ("OUT_SRC_MAC", "Outgoing source MAC address", NetflowV9TypeHandlingMode::MAC));
		hm.insert(82, ("IF_NAME", "Shortened interface name i.e.: 'FE1/0'", NetflowV9TypeHandlingMode::String));
		hm.insert(83, ("IF_DESC", "Full interface name i.e.: 'FastEthernet 1/0'", NetflowV9TypeHandlingMode::String));
		hm.insert(84, ("SAMPLER_NAME", "Name of the flow sampler", NetflowV9TypeHandlingMode::String));
		hm.insert(85, ("IN_PERMANENT_BYTES", "Running byte counter for a permanent flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(86, ("IN_PERMANENT_PKTS", "Running packet counter for a permanent flow", NetflowV9TypeHandlingMode::Number));
		hm.insert(88, ("FRAGMENT_OFFSET", "The fragment-offset value from fragmented IP packets", NetflowV9TypeHandlingMode::Number));
		hm.insert(89, ("FORWARDING STATUS", "Forwarding status is encoded on 1 byte with the 2 left bits giving the status and the 6 remaining bits giving the reason code. Status is either unknown (00), Forwarded (10), Dropped (10) or Consumed (11). Below is the list of forwarding status values with their means. Unknown • 0 Forwarded • Unknown 64 • Forwarded Fragmented 65 • Forwarded not Fragmented 66 Dropped • Unknown 128, • Drop ACL Deny 129, • Drop ACL drop 130, • Drop Unroutable 131, • Drop Adjacency 132, • Drop Fragmentation & DF set 133, • Drop Bad header checksum 134, • Drop Bad total Length 135, • Drop Bad Header Length 136, • Drop bad TTL 137, • Drop Policer 138, • Drop WRED 139, • Drop RPF 140, • Drop For us 141, • Drop Bad output interface 142, • Drop Hardware 143, Consumed • Unknown 192, • Terminate Punt Adjacency 193, • Terminate Incomplete Adjacency 194, • Terminate For us 195", NetflowV9TypeHandlingMode::Number));
		hm.insert(90, ("MPLS PAL RD", "MPLS PAL Route Distinguisher.", NetflowV9TypeHandlingMode::Number));
		hm.insert(91, ("MPLS PREFIX LEN", "Number of consecutive bits in the MPLS prefix length.", NetflowV9TypeHandlingMode::Number));
		hm.insert(92, ("SRC TRAFFIC INDEX", "BGP Policy Accounting Source Traffic Index", NetflowV9TypeHandlingMode::Number));
		hm.insert(93, ("DST TRAFFIC INDEX", "BGP Policy Accounting Destination Traffic Index", NetflowV9TypeHandlingMode::Number));
		hm.insert(94, ("APPLICATION DESCRIPTION", "Application description.", NetflowV9TypeHandlingMode::String));
		hm.insert(95, ("APPLICATION TAG", "8 bits of engine ID, followed by n bits of classification.", NetflowV9TypeHandlingMode::Number));
		hm.insert(96, ("APPLICATION NAME", "Name associated with a classification.", NetflowV9TypeHandlingMode::String));
		hm.insert(98, ("postipDiffServCodePoint", "The value of a Differentiated Services Code Point (DSCP) encoded in the Differentiated Services Field, after modification.", NetflowV9TypeHandlingMode::Number));
		hm.insert(99, ("replication factor", "Multicast replication factor.", NetflowV9TypeHandlingMode::Number));
		hm.insert(102,("layer2packetSectionOffset", "Layer 2 packet section offset. Potentially a generic offset.", NetflowV9TypeHandlingMode::Number));
		hm.insert(103,("layer2packetSectionSize", "Layer 2 packet section size. Potentially a generic size.", NetflowV9TypeHandlingMode::Number));
		hm.insert(104,("layer2packetSectionData", "Layer 2 packet section data.", NetflowV9TypeHandlingMode::Number));
		hm
	};
}
