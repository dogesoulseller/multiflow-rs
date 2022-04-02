//! Mapping for known NetFlow IPFIX types

/// How a data field should be parsed
#[derive(Debug, Clone, Copy)]
pub enum NetflowIPFIXTypeHandlingMode {
	/// 1, 2, 3, 4, or 8-byte unsigned number
	Number,
	/// IPv4 address
	IPv4,
	/// IPv6 address
	IPv6,
	/// 6-byte MAC
	MAC,
	/// String
	String,
	/// 1, 2, 3, 4, or 8-byte signed number
	SignedNumber,
	/// Single or double-precision floating point number
	Float,
	/// Arbitrary array of bytes
	OctetArray,
	/// Boolean value
	Boolean,
	/// 32-bit uinteger representing the number of seconds since unix epoch
	DateTimeSeconds,
	/// 64-bit uinteger representing the number of milliseconds since unix epoch
	DateTimeMillis,
	/// Two 32-bit integers representing the seconds part and fraction parts
	DateTimeMicros,
	/// Two 32-bit integers representing the seconds part and fraction parts
	DateTimeNanos
}

/// Which scope an options template field describes
#[derive(Debug, Clone, Copy)]
pub enum NetflowIPFIXScopeType {
	System = 1,
	Interface = 2,
	LineCard = 3,
	NetFlowCache = 4,
	Template = 5,
}

impl TryFrom<u16> for NetflowIPFIXScopeType {
	type Error = ();

	fn try_from(v: u16) -> Result<Self, Self::Error> {
		match v {
			1 => Ok(Self::System),
			2 => Ok(Self::Interface),
			3 => Ok(Self::LineCard),
			4 => Ok(Self::NetFlowCache),
			5 => Ok(Self::Template),
			_ => Err(())
		}
	}
}

/// Type map content description. Consists of the field name, field description, handling info, and the type ID
pub type NetflowIPFIXTypeInfo = (&'static str, &'static str, NetflowIPFIXTypeHandlingMode, u16);

lazy_static! {
	/// Data type mapping
	pub(crate) static ref NETFLOW_IPFIX_DATATYPES: std::collections::HashMap<u16, NetflowIPFIXTypeInfo> = {
		let mut hm = std::collections::HashMap::with_capacity(128);
		hm.insert(1,  ("IN_BYTES", "Incoming counter with length N x 8 bits for number of bytes associated with an IP Flow.", NetflowIPFIXTypeHandlingMode::Number, 1));
		hm.insert(2,  ("IN_PKTS", "Incoming counter with length N x 8 bits for the number of packets associated with an IP Flow", NetflowIPFIXTypeHandlingMode::Number, 2));
		hm.insert(3,  ("FLOWS", "Number of flows that were aggregated; default for N is 4", NetflowIPFIXTypeHandlingMode::Number, 3));
		hm.insert(4,  ("PROTOCOL", "IP protocol byte", NetflowIPFIXTypeHandlingMode::Number, 4));
		hm.insert(5,  ("SRC_TOS", "Type of Service byte setting when entering incoming interface", NetflowIPFIXTypeHandlingMode::Number, 5));
		hm.insert(6,  ("TCP_FLAGS", "Cumulative of all the TCP flags seen for this flow", NetflowIPFIXTypeHandlingMode::Number, 6));
		hm.insert(7,  ("L4_SRC_PORT", "TCP/UDP source port number i.e.: FTP, Telnet, or equivalent", NetflowIPFIXTypeHandlingMode::Number, 7));
		hm.insert(8,  ("IPV4_SRC_ADDR", "IPv4 source address", NetflowIPFIXTypeHandlingMode::IPv4, 8));
		hm.insert(9,  ("SRC_MASK", "The number of contiguous bits in the source address subnet mask i.e.: the submask in slash notation", NetflowIPFIXTypeHandlingMode::Number, 9));
		hm.insert(10, ("INPUT_SNMP", "Input interface index; default for N is 2 but higher values could be used", NetflowIPFIXTypeHandlingMode::Number, 10));
		hm.insert(11, ("L4_DST_PORT", "TCP/UDP destination port number i.e.: FTP, Telnet, or equivalent", NetflowIPFIXTypeHandlingMode::Number, 11));
		hm.insert(12, ("IPV4_DST_ADDR", "IPv4 destination address", NetflowIPFIXTypeHandlingMode::IPv4, 12));
		hm.insert(13, ("DST_MASK", "The number of contiguous bits in the destination address subnet mask i.e.: the submask in slash notation", NetflowIPFIXTypeHandlingMode::Number, 13));
		hm.insert(14, ("OUTPUT_SNMP", "Output interface index; default for N is 2 but higher values could be used", NetflowIPFIXTypeHandlingMode::Number, 14));
		hm.insert(15, ("IPV4_NEXT_HOP", "IPv4 address of next-hop router", NetflowIPFIXTypeHandlingMode::IPv4, 15));
		hm.insert(16, ("SRC_AS", "Source BGP autonomous system number where N could be 2 or 4", NetflowIPFIXTypeHandlingMode::Number, 16));
		hm.insert(17, ("DST_AS", "Destination BGP autonomous system number where N could be 2 or 4", NetflowIPFIXTypeHandlingMode::Number, 17));
		hm.insert(18, ("BGP_IPV4_NEXT_HOP", "Next-hop router's IP in the BGP domain", NetflowIPFIXTypeHandlingMode::IPv4, 18));
		hm.insert(19, ("MUL_DST_PKTS", "IP multicast outgoing packet counter with length N x 8 bits for packets associated with the IP Flow", NetflowIPFIXTypeHandlingMode::Number, 19));
		hm.insert(20, ("MUL_DST_BYTES", "IP multicast outgoing byte counter with length N x 8 bits for bytes associated with the IP Flow", NetflowIPFIXTypeHandlingMode::Number, 20));
		hm.insert(21, ("LAST_SWITCHED", "System uptime at which the last packet of this flow was switched", NetflowIPFIXTypeHandlingMode::Number, 21));
		hm.insert(22, ("FIRST_SWITCHED", "System uptime at which the first packet of this flow was switched", NetflowIPFIXTypeHandlingMode::Number, 22));
		hm.insert(23, ("OUT_BYTES", "Outgoing counter with length N x 8 bits for the number of bytes associated with an IP Flow", NetflowIPFIXTypeHandlingMode::Number, 23));
		hm.insert(24, ("OUT_PKTS", "Outgoing counter with length N x 8 bits for the number of packets associated with an IP Flow.", NetflowIPFIXTypeHandlingMode::Number, 24));
		hm.insert(25, ("MIN_PKT_LNGTH", "Minimum IP packet length on incoming packets of the flow", NetflowIPFIXTypeHandlingMode::Number, 25));
		hm.insert(26, ("MAX_PKT_LNGTH", "Maximum IP packet length on incoming packets of the flow", NetflowIPFIXTypeHandlingMode::Number, 26));
		hm.insert(27, ("IPV6_SRC_ADDR", "IPv6 Source Address", NetflowIPFIXTypeHandlingMode::IPv6, 27));
		hm.insert(28, ("IPV6_DST_ADDR", "IPv6 Destination Address", NetflowIPFIXTypeHandlingMode::IPv6, 28));
		hm.insert(29, ("IPV6_SRC_MASK", "Length of the IPv6 source mask in contiguous bits", NetflowIPFIXTypeHandlingMode::Number, 29));
		hm.insert(30, ("IPV6_DST_MASK", "Length of the IPv6 destination mask in contiguous bits", NetflowIPFIXTypeHandlingMode::Number, 30));
		hm.insert(31, ("IPV6_FLOW_LABEL", "IPv6 flow label as per RFC 2460 definition", NetflowIPFIXTypeHandlingMode::Number, 31));
		hm.insert(32, ("ICMP_TYPE", "Internet Control Message Protocol (ICMP) packet type; reported as ((ICMP Type*256) + ICMP code)", NetflowIPFIXTypeHandlingMode::Number, 32));
		hm.insert(33, ("MUL_IGMP_TYPE", "Internet Group Management Protocol (IGMP) packet type", NetflowIPFIXTypeHandlingMode::Number, 33));
		hm.insert(34, ("SAMPLING_INTERVAL", "When using sampled NetFlow, the rate at which packets are sampled i.e.: a value of 100 indicates that one of every 100 packets is sampled", NetflowIPFIXTypeHandlingMode::Number, 34));
		hm.insert(35, ("SAMPLING_ALGORITHM", "The type of algorithm used for sampled NetFlow: 0x01 Deterministic Sampling ,0x02 Random Sampling", NetflowIPFIXTypeHandlingMode::Number, 35));
		hm.insert(36, ("FLOW_ACTIVE_TIMEOUT", "Timeout value (in seconds) for active flow entries in the NetFlow cache", NetflowIPFIXTypeHandlingMode::Number, 36));
		hm.insert(37, ("FLOW_INACTIVE_TIMEOUT", "Timeout value (in seconds) for inactive flow entries in the NetFlow cache", NetflowIPFIXTypeHandlingMode::Number, 37));
		hm.insert(38, ("ENGINE_TYPE", "Type of flow switching engine: RP = 0, VIP/Linecard = 1", NetflowIPFIXTypeHandlingMode::Number, 38));
		hm.insert(39, ("ENGINE_ID", "ID number of the flow switching engine", NetflowIPFIXTypeHandlingMode::Number, 39));
		hm.insert(40, ("TOTAL_BYTES_EXP", "Counter with length N x 8 bits for bytes for the number of bytes exported by the Observation Domain", NetflowIPFIXTypeHandlingMode::Number, 40));
		hm.insert(41, ("TOTAL_PKTS_EXP", "Counter with length N x 8 bits for bytes for the number of packets exported by the Observation Domain", NetflowIPFIXTypeHandlingMode::Number, 41));
		hm.insert(42, ("TOTAL_FLOWS_EXP", "Counter with length N x 8 bits for bytes for the number of flows exported by the Observation Domain", NetflowIPFIXTypeHandlingMode::Number, 42));
		hm.insert(44, ("IPV4_SRC_PREFIX", "IPv4 source address prefix (specific for Catalyst architecture)", NetflowIPFIXTypeHandlingMode::Number, 44));
		hm.insert(45, ("IPV4_DST_PREFIX", "IPv4 destination address prefix (specific for Catalyst architecture)", NetflowIPFIXTypeHandlingMode::Number, 45));
		hm.insert(46, ("MPLS_TOP_LABEL_TYPE", "MPLS Top Label Type: 0x00 UNKNOWN 0x01 TE-MIDPT 0x02 ATOM 0x03 VPN 0x04 BGP 0x05 LDP", NetflowIPFIXTypeHandlingMode::Number, 46));
		hm.insert(47, ("MPLS_TOP_LABEL_IP_ADDR", "Forwarding Equivalent Class corresponding to the MPLS Top Label", NetflowIPFIXTypeHandlingMode::Number, 47));
		hm.insert(48, ("FLOW_SAMPLER_ID", "Identifier shown in 'show flow-sampler'", NetflowIPFIXTypeHandlingMode::Number, 48));
		hm.insert(49, ("FLOW_SAMPLER_MODE", "The type of algorithm used for sampling data: 0x02 random sampling. Use in connection with FLOW_SAMPLER_MODE", NetflowIPFIXTypeHandlingMode::Number, 49));
		hm.insert(50, ("FLOW_SAMPLER_RANDOM_INTERVAL", "Packet interval at which to sample. Use in connection with FLOW_SAMPLER_MODE", NetflowIPFIXTypeHandlingMode::Number, 50));
		hm.insert(52, ("MIN_TTL", "Minimum TTL on incoming packets of the flow", NetflowIPFIXTypeHandlingMode::Number, 52));
		hm.insert(53, ("MAX_TTL", "Maximum TTL on incoming packets of the flow", NetflowIPFIXTypeHandlingMode::Number, 53));
		hm.insert(54, ("IPV4_IDENT", "The IP v4 identification field", NetflowIPFIXTypeHandlingMode::Number, 54));
		hm.insert(55, ("DST_TOS", "Type of Service byte setting when exiting outgoing interface", NetflowIPFIXTypeHandlingMode::Number, 55));
		hm.insert(56, ("IN_SRC_MAC", "Incoming source MAC address", NetflowIPFIXTypeHandlingMode::MAC, 56));
		hm.insert(57, ("OUT_DST_MAC", "Outgoing destination MAC address", NetflowIPFIXTypeHandlingMode::MAC, 57));
		hm.insert(58, ("SRC_VLAN", "Virtual LAN identifier associated with ingress interface", NetflowIPFIXTypeHandlingMode::Number, 58));
		hm.insert(59, ("DST_VLAN", "Virtual LAN identifier associated with egress interface", NetflowIPFIXTypeHandlingMode::Number, 59));
		hm.insert(60, ("IP_PROTOCOL_VERSION", "Internet Protocol Version Set to 4 for IPv4, set to 6 for IPv6. If not present in the template, then version 4 is assumed.", NetflowIPFIXTypeHandlingMode::Number, 60));
		hm.insert(61, ("DIRECTION", "Flow direction: 0 - ingress flow, 1 - egress flow", NetflowIPFIXTypeHandlingMode::Number, 61));
		hm.insert(62, ("IPV6_NEXT_HOP", "IPv6 address of the next-hop router", NetflowIPFIXTypeHandlingMode::IPv6, 62));
		hm.insert(63, ("BPG_IPV6_NEXT_HOP", "Next-hop router in the BGP domain", NetflowIPFIXTypeHandlingMode::IPv6, 63));
		hm.insert(64, ("IPV6_OPTION_HEADERS", "Bit-encoded field identifying IPv6 option headers found in the flow", NetflowIPFIXTypeHandlingMode::Number, 64));
		hm.insert(70, ("MPLS_LABEL_1", "MPLS label at position 1 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowIPFIXTypeHandlingMode::Number, 70));
		hm.insert(71, ("MPLS_LABEL_2", "MPLS label at position 2 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowIPFIXTypeHandlingMode::Number, 71));
		hm.insert(72, ("MPLS_LABEL_3", "MPLS label at position 3 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowIPFIXTypeHandlingMode::Number, 72));
		hm.insert(73, ("MPLS_LABEL_4", "MPLS label at position 4 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowIPFIXTypeHandlingMode::Number, 73));
		hm.insert(74, ("MPLS_LABEL_5", "MPLS label at position 5 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowIPFIXTypeHandlingMode::Number, 74));
		hm.insert(75, ("MPLS_LABEL_6", "MPLS label at position 6 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowIPFIXTypeHandlingMode::Number, 75));
		hm.insert(76, ("MPLS_LABEL_7", "MPLS label at position 7 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowIPFIXTypeHandlingMode::Number, 76));
		hm.insert(77, ("MPLS_LABEL_8", "MPLS label at position 8 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowIPFIXTypeHandlingMode::Number, 77));
		hm.insert(78, ("MPLS_LABEL_9", "MPLS label at position 9 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowIPFIXTypeHandlingMode::Number, 78));
		hm.insert(79, ("MPLS_LABEL_10", "MPLS label at position 10 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.", NetflowIPFIXTypeHandlingMode::Number, 79));
		hm.insert(80, ("IN_DST_MAC", "Incoming destination MAC address", NetflowIPFIXTypeHandlingMode::MAC, 80));
		hm.insert(81, ("OUT_SRC_MAC", "Outgoing source MAC address", NetflowIPFIXTypeHandlingMode::MAC, 81));
		hm.insert(82, ("IF_NAME", "Shortened interface name i.e.: 'FE1/0'", NetflowIPFIXTypeHandlingMode::String, 82));
		hm.insert(83, ("IF_DESC", "Full interface name i.e.: 'FastEthernet 1/0'", NetflowIPFIXTypeHandlingMode::String, 83));
		hm.insert(84, ("SAMPLER_NAME", "Name of the flow sampler", NetflowIPFIXTypeHandlingMode::String, 84));
		hm.insert(85, ("IN_PERMANENT_BYTES", "Running byte counter for a permanent flow", NetflowIPFIXTypeHandlingMode::Number, 85));
		hm.insert(86, ("IN_PERMANENT_PKTS", "Running packet counter for a permanent flow", NetflowIPFIXTypeHandlingMode::Number, 86));
		hm.insert(88, ("FRAGMENT_OFFSET", "The fragment-offset value from fragmented IP packets", NetflowIPFIXTypeHandlingMode::Number, 88));
		hm.insert(89, ("FORWARDING STATUS", "Forwarding status is encoded on 1 byte with the 2 left bits giving the status and the 6 remaining bits giving the reason code. Status is either unknown (00), Forwarded (10), Dropped (10) or Consumed (11). Below is the list of forwarding status values with their means. Unknown • 0 Forwarded • Unknown 64 • Forwarded Fragmented 65 • Forwarded not Fragmented 66 Dropped • Unknown 128, • Drop ACL Deny 129, • Drop ACL drop 130, • Drop Unroutable 131, • Drop Adjacency 132, • Drop Fragmentation & DF set 133, • Drop Bad header checksum 134, • Drop Bad total Length 135, • Drop Bad Header Length 136, • Drop bad TTL 137, • Drop Policer 138, • Drop WRED 139, • Drop RPF 140, • Drop For us 141, • Drop Bad output interface 142, • Drop Hardware 143, Consumed • Unknown 192, • Terminate Punt Adjacency 193, • Terminate Incomplete Adjacency 194, • Terminate For us 195", NetflowIPFIXTypeHandlingMode::Number, 89));
		hm.insert(90, ("MPLS PAL RD", "MPLS PAL Route Distinguisher.", NetflowIPFIXTypeHandlingMode::Number, 90));
		hm.insert(91, ("MPLS PREFIX LEN", "Number of consecutive bits in the MPLS prefix length.", NetflowIPFIXTypeHandlingMode::Number, 91));
		hm.insert(92, ("SRC TRAFFIC INDEX", "BGP Policy Accounting Source Traffic Index", NetflowIPFIXTypeHandlingMode::Number, 92));
		hm.insert(93, ("DST TRAFFIC INDEX", "BGP Policy Accounting Destination Traffic Index", NetflowIPFIXTypeHandlingMode::Number, 93));
		hm.insert(94, ("APPLICATION DESCRIPTION", "Application description.", NetflowIPFIXTypeHandlingMode::String, 94));
		hm.insert(95, ("APPLICATION TAG", "8 bits of engine ID, followed by n bits of classification.", NetflowIPFIXTypeHandlingMode::Number, 95));
		hm.insert(96, ("APPLICATION NAME", "Name associated with a classification.", NetflowIPFIXTypeHandlingMode::String, 96));
		hm.insert(98, ("postipDiffServCodePoint", "The value of a Differentiated Services Code Point (DSCP) encoded in the Differentiated Services Field, after modification.", NetflowIPFIXTypeHandlingMode::Number, 98));
		hm.insert(99, ("replication factor", "Multicast replication factor.", NetflowIPFIXTypeHandlingMode::Number, 99));
		hm.insert(102,("layer2packetSectionOffset", "Layer 2 packet section offset. Potentially a generic offset.", NetflowIPFIXTypeHandlingMode::Number, 102));
		hm.insert(103,("layer2packetSectionSize", "Layer 2 packet section size. Potentially a generic size.", NetflowIPFIXTypeHandlingMode::Number, 103));
		hm.insert(104,("layer2packetSectionData", "Layer 2 packet section data.", NetflowIPFIXTypeHandlingMode::Number, 104));

		hm.insert(128, ("bgpNextAdjacentAsNumber", "", NetflowIPFIXTypeHandlingMode::Number, 128));
		hm.insert(129, ("bgpPrevAdjacentAsNumber", "", NetflowIPFIXTypeHandlingMode::Number, 129));
		hm.insert(130, ("exporterIPv4Address", "", NetflowIPFIXTypeHandlingMode::IPv4, 130));
		hm.insert(131, ("exporterIPv6Address", "", NetflowIPFIXTypeHandlingMode::IPv6, 131));
		hm.insert(132, ("droppedOctetDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 132));
		hm.insert(133, ("droppedPacketDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 133));
		hm.insert(134, ("droppedOctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 134));
		hm.insert(135, ("droppedPacketTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 135));
		hm.insert(136, ("flowEndReason", "", NetflowIPFIXTypeHandlingMode::Number, 136));
		hm.insert(137, ("commonPropertiesId", "", NetflowIPFIXTypeHandlingMode::Number, 137));
		hm.insert(138, ("observationPointId", "", NetflowIPFIXTypeHandlingMode::Number, 138));
		hm.insert(139, ("icmpTypeCodeIPv6", "", NetflowIPFIXTypeHandlingMode::Number, 139));
		hm.insert(140, ("mplsTopLabelIPv6Address", "", NetflowIPFIXTypeHandlingMode::IPv6, 140));
		hm.insert(141, ("lineCardId", "", NetflowIPFIXTypeHandlingMode::Number, 141));
		hm.insert(142, ("portId", "", NetflowIPFIXTypeHandlingMode::Number, 142));
		hm.insert(143, ("meteringProcessId", "", NetflowIPFIXTypeHandlingMode::Number, 143));
		hm.insert(144, ("exportingProcessId", "", NetflowIPFIXTypeHandlingMode::Number, 144));
		hm.insert(145, ("templateId", "", NetflowIPFIXTypeHandlingMode::Number, 145));
		hm.insert(146, ("wlanChannelId", "", NetflowIPFIXTypeHandlingMode::Number, 146));
		hm.insert(147, ("wlanSSID", "", NetflowIPFIXTypeHandlingMode::String, 147));
		hm.insert(148, ("flowId", "", NetflowIPFIXTypeHandlingMode::Number, 148));
		hm.insert(149, ("observationDomainId", "", NetflowIPFIXTypeHandlingMode::Number, 149));
		hm.insert(150, ("flowStartSeconds", "", NetflowIPFIXTypeHandlingMode::DateTimeSeconds, 150));
		hm.insert(151, ("flowEndSeconds", "", NetflowIPFIXTypeHandlingMode::DateTimeSeconds, 151));
		hm.insert(152, ("flowStartMilliseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMillis, 152));
		hm.insert(153, ("flowEndMilliseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMillis, 153));
		hm.insert(154, ("flowStartMicroseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMicros, 154));
		hm.insert(155, ("flowEndMicroseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMicros, 155));
		hm.insert(156, ("flowStartNanoseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeNanos, 156));
		hm.insert(157, ("flowEndNanoseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeNanos, 157));
		hm.insert(158, ("flowStartDeltaMicroseconds", "", NetflowIPFIXTypeHandlingMode::Number, 158));
		hm.insert(159, ("flowEndDeltaMicroseconds", "", NetflowIPFIXTypeHandlingMode::Number, 159));
		hm.insert(160, ("systemInitTimeMilliseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMillis, 160));
		hm.insert(161, ("flowDurationMilliseconds", "", NetflowIPFIXTypeHandlingMode::Number, 161));
		hm.insert(162, ("flowDurationMicroseconds", "", NetflowIPFIXTypeHandlingMode::Number, 162));
		hm.insert(163, ("observedFlowTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 163));
		hm.insert(164, ("ignoredPacketTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 164));
		hm.insert(165, ("ignoredOctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 165));
		hm.insert(166, ("notSentFlowTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 166));
		hm.insert(167, ("notSentPacketTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 167));
		hm.insert(168, ("notSentOctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 168));
		hm.insert(169, ("destinationIPv6Prefix", "", NetflowIPFIXTypeHandlingMode::IPv6, 169));
		hm.insert(170, ("sourceIPv6Prefix", "", NetflowIPFIXTypeHandlingMode::IPv6, 170));
		hm.insert(171, ("postOctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 171));
		hm.insert(172, ("postPacketTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 172));
		hm.insert(173, ("flowKeyIndicator", "", NetflowIPFIXTypeHandlingMode::Number, 173));
		hm.insert(174, ("postMCastPacketTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 174));
		hm.insert(175, ("postMCastOctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 175));
		hm.insert(176, ("icmpTypeIPv4", "", NetflowIPFIXTypeHandlingMode::Number, 176));
		hm.insert(177, ("icmpCodeIPv4", "", NetflowIPFIXTypeHandlingMode::Number, 177));
		hm.insert(178, ("icmpTypeIPv6", "", NetflowIPFIXTypeHandlingMode::Number, 178));
		hm.insert(179, ("icmpCodeIPv6", "", NetflowIPFIXTypeHandlingMode::Number, 179));
		hm.insert(180, ("udpSourcePort", "", NetflowIPFIXTypeHandlingMode::Number, 180));
		hm.insert(181, ("udpDestinationPort", "", NetflowIPFIXTypeHandlingMode::Number, 181));
		hm.insert(182, ("tcpSourcePort", "", NetflowIPFIXTypeHandlingMode::Number, 182));
		hm.insert(183, ("tcpDestinationPort", "", NetflowIPFIXTypeHandlingMode::Number, 183));
		hm.insert(184, ("tcpSequenceNumber", "", NetflowIPFIXTypeHandlingMode::Number, 184));
		hm.insert(185, ("tcpAcknowledgementNumber", "", NetflowIPFIXTypeHandlingMode::Number, 185));
		hm.insert(186, ("tcpWindowSize", "", NetflowIPFIXTypeHandlingMode::Number, 186));
		hm.insert(187, ("tcpUrgentPointer", "", NetflowIPFIXTypeHandlingMode::Number, 187));
		hm.insert(188, ("tcpHeaderLength", "", NetflowIPFIXTypeHandlingMode::Number, 188));
		hm.insert(189, ("ipHeaderLength", "", NetflowIPFIXTypeHandlingMode::Number, 189));
		hm.insert(190, ("totalLengthIPv4", "", NetflowIPFIXTypeHandlingMode::Number, 190));
		hm.insert(191, ("payloadLengthIPv6", "", NetflowIPFIXTypeHandlingMode::Number, 191));
		hm.insert(192, ("ipTTL", "", NetflowIPFIXTypeHandlingMode::Number, 192));
		hm.insert(193, ("nextHeaderIPv6", "", NetflowIPFIXTypeHandlingMode::Number, 193));
		hm.insert(194, ("mplsPayloadLength", "", NetflowIPFIXTypeHandlingMode::Number, 194));
		hm.insert(195, ("ipDiffServCodePoint", "", NetflowIPFIXTypeHandlingMode::Number, 195));
		hm.insert(196, ("ipPrecedence", "", NetflowIPFIXTypeHandlingMode::Number, 196));
		hm.insert(197, ("fragmentFlags", "", NetflowIPFIXTypeHandlingMode::Number, 197));
		hm.insert(198, ("octetDeltaSumOfSquares", "", NetflowIPFIXTypeHandlingMode::Number, 198));
		hm.insert(199, ("octetTotalSumOfSquares", "", NetflowIPFIXTypeHandlingMode::Number, 199));
		hm.insert(200, ("mplsTopLabelTTL", "", NetflowIPFIXTypeHandlingMode::Number, 200));
		hm.insert(201, ("mplsLabelStackLength", "", NetflowIPFIXTypeHandlingMode::Number, 201));
		hm.insert(202, ("mplsLabelStackDepth", "", NetflowIPFIXTypeHandlingMode::Number, 202));
		hm.insert(203, ("mplsTopLabelExp", "", NetflowIPFIXTypeHandlingMode::Number, 203));
		hm.insert(204, ("ipPayloadLength", "", NetflowIPFIXTypeHandlingMode::Number, 204));
		hm.insert(205, ("udpMessageLength", "", NetflowIPFIXTypeHandlingMode::Number, 205));
		hm.insert(206, ("isMulticast", "", NetflowIPFIXTypeHandlingMode::Number, 206));
		hm.insert(207, ("ipv4IHL", "", NetflowIPFIXTypeHandlingMode::Number, 207));
		hm.insert(208, ("ipv4Options", "", NetflowIPFIXTypeHandlingMode::Number, 208));
		hm.insert(209, ("tcpOptions", "", NetflowIPFIXTypeHandlingMode::Number, 209));
		hm.insert(210, ("paddingOctets", "", NetflowIPFIXTypeHandlingMode::OctetArray, 210));
		hm.insert(211, ("collectorIPv4Address", "", NetflowIPFIXTypeHandlingMode::IPv4, 211));
		hm.insert(212, ("collectorIPv6Address", "", NetflowIPFIXTypeHandlingMode::IPv6, 212));
		hm.insert(213, ("exportInterface", "", NetflowIPFIXTypeHandlingMode::Number, 213));
		hm.insert(214, ("exportProtocolVersion", "", NetflowIPFIXTypeHandlingMode::Number, 214));
		hm.insert(215, ("exportTransportProtocol", "", NetflowIPFIXTypeHandlingMode::Number, 215));
		hm.insert(216, ("collectorTransportPort", "", NetflowIPFIXTypeHandlingMode::Number, 216));
		hm.insert(217, ("exporterTransportPort", "", NetflowIPFIXTypeHandlingMode::Number, 217));
		hm.insert(218, ("tcpSynTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 218));
		hm.insert(219, ("tcpFinTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 219));
		hm.insert(220, ("tcpRstTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 220));
		hm.insert(221, ("tcpPshTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 221));
		hm.insert(222, ("tcpAckTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 222));
		hm.insert(223, ("tcpUrgTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 223));
		hm.insert(224, ("ipTotalLength", "", NetflowIPFIXTypeHandlingMode::Number, 224));
		hm.insert(225, ("postNATSourceIPv4Address", "", NetflowIPFIXTypeHandlingMode::IPv4, 225));
		hm.insert(226, ("postNATDestinationIPv4Address", "", NetflowIPFIXTypeHandlingMode::IPv4, 226));
		hm.insert(227, ("postNAPTSourceTransportPort", "", NetflowIPFIXTypeHandlingMode::Number, 227));
		hm.insert(228, ("postNAPTDestinationTransportPort", "", NetflowIPFIXTypeHandlingMode::Number, 228));
		hm.insert(229, ("natOriginatingAddressRealm", "", NetflowIPFIXTypeHandlingMode::Number, 229));
		hm.insert(230, ("natEvent", "", NetflowIPFIXTypeHandlingMode::Number, 230));
		hm.insert(231, ("initiatorOctets", "", NetflowIPFIXTypeHandlingMode::Number, 231));
		hm.insert(232, ("responderOctets", "", NetflowIPFIXTypeHandlingMode::Number, 232));
		hm.insert(233, ("firewallEvent", "", NetflowIPFIXTypeHandlingMode::Number, 233));
		hm.insert(234, ("ingressVRFID", "", NetflowIPFIXTypeHandlingMode::Number, 234));
		hm.insert(235, ("egressVRFID", "", NetflowIPFIXTypeHandlingMode::Number, 235));
		hm.insert(236, ("VRFname", "", NetflowIPFIXTypeHandlingMode::String, 236));
		hm.insert(237, ("postMplsTopLabelExp", "", NetflowIPFIXTypeHandlingMode::Number, 237));
		hm.insert(238, ("tcpWindowScale", "", NetflowIPFIXTypeHandlingMode::Number, 238));
		hm.insert(239, ("biflowDirection", "", NetflowIPFIXTypeHandlingMode::Number, 239));
		hm.insert(240, ("ethernetHeaderLength", "", NetflowIPFIXTypeHandlingMode::Number, 240));
		hm.insert(241, ("ethernetPayloadLength", "", NetflowIPFIXTypeHandlingMode::Number, 241));
		hm.insert(242, ("ethernetTotalLength", "", NetflowIPFIXTypeHandlingMode::Number, 242));
		hm.insert(243, ("dot1qVlanId", "", NetflowIPFIXTypeHandlingMode::Number, 243));
		hm.insert(244, ("dot1qPriority", "", NetflowIPFIXTypeHandlingMode::Number, 244));
		hm.insert(245, ("dot1qCustomerVlanId", "", NetflowIPFIXTypeHandlingMode::Number, 245));
		hm.insert(246, ("dot1qCustomerPriority", "", NetflowIPFIXTypeHandlingMode::Number, 246));
		hm.insert(247, ("metroEvcId", "", NetflowIPFIXTypeHandlingMode::String, 247));
		hm.insert(248, ("metroEvcType", "", NetflowIPFIXTypeHandlingMode::Number, 248));
		hm.insert(249, ("pseudoWireId", "", NetflowIPFIXTypeHandlingMode::Number, 249));
		hm.insert(250, ("pseudoWireType", "", NetflowIPFIXTypeHandlingMode::Number, 250));
		hm.insert(251, ("pseudoWireControlWord", "", NetflowIPFIXTypeHandlingMode::Number, 251));
		hm.insert(252, ("ingressPhysicalInterface", "", NetflowIPFIXTypeHandlingMode::Number, 252));
		hm.insert(253, ("egressPhysicalInterface", "", NetflowIPFIXTypeHandlingMode::Number, 253));
		hm.insert(254, ("postDot1qVlanId", "", NetflowIPFIXTypeHandlingMode::Number, 254));
		hm.insert(255, ("postDot1qCustomerVlanId", "", NetflowIPFIXTypeHandlingMode::Number, 255));
		hm.insert(256, ("ethernetType", "", NetflowIPFIXTypeHandlingMode::Number, 256));
		hm.insert(257, ("postIpPrecedence", "", NetflowIPFIXTypeHandlingMode::Number, 257));
		hm.insert(258, ("collectionTimeMilliseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMillis, 258));
		hm.insert(259, ("exportSctpStreamId", "", NetflowIPFIXTypeHandlingMode::Number, 259));
		hm.insert(260, ("maxExportSeconds", "", NetflowIPFIXTypeHandlingMode::DateTimeSeconds, 260));
		hm.insert(261, ("maxFlowEndSeconds", "", NetflowIPFIXTypeHandlingMode::DateTimeSeconds, 261));
		hm.insert(262, ("messageMD5Checksum", "", NetflowIPFIXTypeHandlingMode::OctetArray, 262));
		hm.insert(263, ("messageScope", "", NetflowIPFIXTypeHandlingMode::Number, 263));
		hm.insert(264, ("minExportSeconds", "", NetflowIPFIXTypeHandlingMode::DateTimeSeconds, 264));
		hm.insert(265, ("minFlowStartSeconds", "", NetflowIPFIXTypeHandlingMode::DateTimeSeconds, 265));
		hm.insert(266, ("opaqueOctets", "", NetflowIPFIXTypeHandlingMode::OctetArray, 266));
		hm.insert(267, ("sessionScope", "", NetflowIPFIXTypeHandlingMode::Number, 267));
		hm.insert(268, ("maxFlowEndMicroseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMicros, 268));
		hm.insert(269, ("maxFlowEndMilliseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMillis, 269));
		hm.insert(270, ("maxFlowEndNanoseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeNanos, 270));
		hm.insert(271, ("minFlowStartMicroseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMicros, 271));
		hm.insert(272, ("minFlowStartMilliseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMillis, 272));
		hm.insert(273, ("minFlowStartNanoseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeNanos, 273));
		hm.insert(274, ("collectorCertificate", "", NetflowIPFIXTypeHandlingMode::OctetArray, 274));
		hm.insert(275, ("exporterCertificate", "", NetflowIPFIXTypeHandlingMode::OctetArray, 275));
		hm.insert(276, ("dataRecordsReliability", "", NetflowIPFIXTypeHandlingMode::Boolean, 276));
		hm.insert(277, ("observationPointType", "", NetflowIPFIXTypeHandlingMode::Number, 277));
		hm.insert(278, ("newConnectionDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 278));
		hm.insert(279, ("connectionSumDurationSeconds", "", NetflowIPFIXTypeHandlingMode::Number, 279));
		hm.insert(280, ("connectionTransactionId", "", NetflowIPFIXTypeHandlingMode::Number, 280));
		hm.insert(281, ("postNATSourceIPv6Address", "", NetflowIPFIXTypeHandlingMode::IPv6, 281));
		hm.insert(282, ("postNATDestinationIPv6Address", "", NetflowIPFIXTypeHandlingMode::IPv6, 282));
		hm.insert(283, ("natPoolId", "", NetflowIPFIXTypeHandlingMode::Number, 283));
		hm.insert(284, ("natPoolName", "", NetflowIPFIXTypeHandlingMode::String, 284));
		hm.insert(285, ("anonymizationFlags", "", NetflowIPFIXTypeHandlingMode::Number, 285));
		hm.insert(286, ("anonymizationTechnique", "", NetflowIPFIXTypeHandlingMode::Number, 286));
		hm.insert(287, ("informationElementIndex", "", NetflowIPFIXTypeHandlingMode::Number, 287));
		hm.insert(288, ("p2pTechnology", "", NetflowIPFIXTypeHandlingMode::String, 288));
		hm.insert(289, ("tunnelTechnology", "", NetflowIPFIXTypeHandlingMode::String, 289));
		hm.insert(290, ("encryptedTechnology", "", NetflowIPFIXTypeHandlingMode::String, 290));
		hm.insert(291, ("basicList", "", NetflowIPFIXTypeHandlingMode::OctetArray, 291));
		hm.insert(292, ("subTemplateList", "", NetflowIPFIXTypeHandlingMode::OctetArray, 292));
		hm.insert(293, ("subTemplateMultiList", "", NetflowIPFIXTypeHandlingMode::OctetArray, 293));
		hm.insert(294, ("bgpValidityState", "", NetflowIPFIXTypeHandlingMode::Number, 294));
		hm.insert(295, ("IPSecSPI", "", NetflowIPFIXTypeHandlingMode::Number, 295));
		hm.insert(296, ("greKey", "", NetflowIPFIXTypeHandlingMode::Number, 296));
		hm.insert(297, ("natType", "", NetflowIPFIXTypeHandlingMode::Number, 297));
		hm.insert(298, ("initiatorPackets", "", NetflowIPFIXTypeHandlingMode::Number, 298));
		hm.insert(299, ("responderPackets", "", NetflowIPFIXTypeHandlingMode::Number, 299));
		hm.insert(300, ("observationDomainName", "", NetflowIPFIXTypeHandlingMode::String, 300));
		hm.insert(301, ("selectionSequenceId", "", NetflowIPFIXTypeHandlingMode::Number, 301));
		hm.insert(302, ("selectorId", "", NetflowIPFIXTypeHandlingMode::Number, 302));
		hm.insert(303, ("informationElementId", "", NetflowIPFIXTypeHandlingMode::Number, 303));
		hm.insert(304, ("selectorAlgorithm", "", NetflowIPFIXTypeHandlingMode::Number, 304));
		hm.insert(305, ("samplingPacketInterval", "", NetflowIPFIXTypeHandlingMode::Number, 305));
		hm.insert(306, ("samplingPacketSpace", "", NetflowIPFIXTypeHandlingMode::Number, 306));
		hm.insert(307, ("samplingTimeInterval", "", NetflowIPFIXTypeHandlingMode::Number, 307));
		hm.insert(308, ("samplingTimeSpace", "", NetflowIPFIXTypeHandlingMode::Number, 308));
		hm.insert(309, ("samplingSize", "", NetflowIPFIXTypeHandlingMode::Number, 309));
		hm.insert(310, ("samplingPopulation", "", NetflowIPFIXTypeHandlingMode::Number, 310));
		hm.insert(311, ("samplingProbability", "", NetflowIPFIXTypeHandlingMode::Float, 311));
		hm.insert(312, ("dataLinkFrameSize", "", NetflowIPFIXTypeHandlingMode::Number, 312));
		hm.insert(313, ("ipHeaderPacketSection", "", NetflowIPFIXTypeHandlingMode::OctetArray, 313));
		hm.insert(314, ("ipPayloadPacketSection", "", NetflowIPFIXTypeHandlingMode::OctetArray, 314));
		hm.insert(315, ("dataLinkFrameSection", "", NetflowIPFIXTypeHandlingMode::OctetArray, 315));
		hm.insert(316, ("mplsLabelStackSection", "", NetflowIPFIXTypeHandlingMode::OctetArray, 316));
		hm.insert(317, ("mplsPayloadPacketSection", "", NetflowIPFIXTypeHandlingMode::OctetArray, 317));
		hm.insert(318, ("selectorIdTotalPktsObserved", "", NetflowIPFIXTypeHandlingMode::Number, 318));
		hm.insert(319, ("selectorIdTotalPktsSelected", "", NetflowIPFIXTypeHandlingMode::Number, 319));
		hm.insert(320, ("absoluteError", "", NetflowIPFIXTypeHandlingMode::Float, 320));
		hm.insert(321, ("relativeError", "", NetflowIPFIXTypeHandlingMode::Float, 321));
		hm.insert(322, ("observationTimeSeconds", "", NetflowIPFIXTypeHandlingMode::DateTimeSeconds, 322));
		hm.insert(323, ("observationTimeMilliseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMillis, 323));
		hm.insert(324, ("observationTimeMicroseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMicros, 324));
		hm.insert(325, ("observationTimeNanoseconds", "", NetflowIPFIXTypeHandlingMode::DateTimeNanos, 325));
		hm.insert(326, ("digestHashValue", "", NetflowIPFIXTypeHandlingMode::Number, 326));
		hm.insert(327, ("hashIPPayloadOffset", "", NetflowIPFIXTypeHandlingMode::Number, 327));
		hm.insert(328, ("hashIPPayloadSize", "", NetflowIPFIXTypeHandlingMode::Number, 328));
		hm.insert(329, ("hashOutputRangeMin", "", NetflowIPFIXTypeHandlingMode::Number, 329));
		hm.insert(330, ("hashOutputRangeMax", "", NetflowIPFIXTypeHandlingMode::Number, 330));
		hm.insert(331, ("hashSelectedRangeMin", "", NetflowIPFIXTypeHandlingMode::Number, 331));
		hm.insert(332, ("hashSelectedRangeMax", "", NetflowIPFIXTypeHandlingMode::Number, 332));
		hm.insert(333, ("hashDigestOutput", "", NetflowIPFIXTypeHandlingMode::Boolean, 333));
		hm.insert(334, ("hashInitialiserValue", "", NetflowIPFIXTypeHandlingMode::Number, 334));
		hm.insert(335, ("selectorName", "", NetflowIPFIXTypeHandlingMode::String, 335));
		hm.insert(336, ("upperCILimit", "", NetflowIPFIXTypeHandlingMode::Float, 336));
		hm.insert(337, ("lowerCILimit", "", NetflowIPFIXTypeHandlingMode::Float, 337));
		hm.insert(338, ("confidenceLevel", "", NetflowIPFIXTypeHandlingMode::Float, 338));
		hm.insert(339, ("informationElementDataType", "", NetflowIPFIXTypeHandlingMode::Number, 339));
		hm.insert(340, ("informationElementDescription", "", NetflowIPFIXTypeHandlingMode::String, 340));
		hm.insert(341, ("informationElementName", "", NetflowIPFIXTypeHandlingMode::String, 341));
		hm.insert(342, ("informationElementRangeBegin", "", NetflowIPFIXTypeHandlingMode::Number, 342));
		hm.insert(343, ("informationElementRangeEnd", "", NetflowIPFIXTypeHandlingMode::Number, 343));
		hm.insert(344, ("informationElementSemantics", "", NetflowIPFIXTypeHandlingMode::Number, 344));
		hm.insert(345, ("informationElementUnits", "", NetflowIPFIXTypeHandlingMode::Number, 345));
		hm.insert(346, ("privateEnterpriseNumber", "", NetflowIPFIXTypeHandlingMode::Number, 346));
		hm.insert(347, ("virtualStationInterfaceId", "", NetflowIPFIXTypeHandlingMode::OctetArray, 347));
		hm.insert(348, ("virtualStationInterfaceName", "", NetflowIPFIXTypeHandlingMode::String, 348));
		hm.insert(349, ("virtualStationUUID", "", NetflowIPFIXTypeHandlingMode::OctetArray, 349));
		hm.insert(350, ("virtualStationName", "", NetflowIPFIXTypeHandlingMode::String, 350));
		hm.insert(351, ("layer2SegmentId", "", NetflowIPFIXTypeHandlingMode::Number, 351));
		hm.insert(352, ("layer2OctetDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 352));
		hm.insert(353, ("layer2OctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 353));
		hm.insert(354, ("ingressUnicastPacketTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 354));
		hm.insert(355, ("ingressMulticastPacketTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 355));
		hm.insert(356, ("ingressBroadcastPacketTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 356));
		hm.insert(357, ("egressUnicastPacketTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 357));
		hm.insert(358, ("egressBroadcastPacketTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 358));
		hm.insert(359, ("monitoringIntervalStartMilliSeconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMillis, 359));
		hm.insert(360, ("monitoringIntervalEndMilliSeconds", "", NetflowIPFIXTypeHandlingMode::DateTimeMillis, 360));
		hm.insert(361, ("portRangeStart", "", NetflowIPFIXTypeHandlingMode::Number, 361));
		hm.insert(362, ("portRangeEnd", "", NetflowIPFIXTypeHandlingMode::Number, 362));
		hm.insert(363, ("portRangeStepSize", "", NetflowIPFIXTypeHandlingMode::Number, 363));
		hm.insert(364, ("portRangeNumPorts", "", NetflowIPFIXTypeHandlingMode::Number, 364));
		hm.insert(365, ("staMacAddress", "", NetflowIPFIXTypeHandlingMode::MAC, 365));
		hm.insert(366, ("staIPv4Address", "", NetflowIPFIXTypeHandlingMode::IPv4, 366));
		hm.insert(367, ("wtpMacAddress", "", NetflowIPFIXTypeHandlingMode::MAC, 367));
		hm.insert(368, ("ingressInterfaceType", "", NetflowIPFIXTypeHandlingMode::Number, 368));
		hm.insert(369, ("egressInterfaceType", "", NetflowIPFIXTypeHandlingMode::Number, 369));
		hm.insert(370, ("rtpSequenceNumber", "", NetflowIPFIXTypeHandlingMode::Number, 370));
		hm.insert(371, ("userName", "", NetflowIPFIXTypeHandlingMode::String, 371));
		hm.insert(372, ("applicationCategoryName", "", NetflowIPFIXTypeHandlingMode::String, 372));
		hm.insert(373, ("applicationSubCategoryName", "", NetflowIPFIXTypeHandlingMode::String, 373));
		hm.insert(374, ("applicationGroupName", "", NetflowIPFIXTypeHandlingMode::String, 374));
		hm.insert(375, ("originalFlowsPresent", "", NetflowIPFIXTypeHandlingMode::Number, 375));
		hm.insert(376, ("originalFlowsInitiated", "", NetflowIPFIXTypeHandlingMode::Number, 376));
		hm.insert(377, ("originalFlowsCompleted", "", NetflowIPFIXTypeHandlingMode::Number, 377));
		hm.insert(378, ("distinctCountOfSourceIPAddress", "", NetflowIPFIXTypeHandlingMode::Number, 378));
		hm.insert(379, ("distinctCountOfDestinationIPAddress", "", NetflowIPFIXTypeHandlingMode::Number, 379));
		hm.insert(380, ("distinctCountOfSourceIPv4Address", "", NetflowIPFIXTypeHandlingMode::Number, 380));
		hm.insert(381, ("distinctCountOfDestinationIPv4Address", "", NetflowIPFIXTypeHandlingMode::Number, 381));
		hm.insert(382, ("distinctCountOfSourceIPv6Address", "", NetflowIPFIXTypeHandlingMode::Number, 382));
		hm.insert(383, ("distinctCountOfDestinationIPv6Address", "", NetflowIPFIXTypeHandlingMode::Number, 383));
		hm.insert(384, ("valueDistributionMethod", "", NetflowIPFIXTypeHandlingMode::Number, 384));
		hm.insert(385, ("rfc3550JitterMilliseconds", "", NetflowIPFIXTypeHandlingMode::Number, 385));
		hm.insert(386, ("rfc3550JitterMicroseconds", "", NetflowIPFIXTypeHandlingMode::Number, 386));
		hm.insert(387, ("rfc3550JitterNanoseconds", "", NetflowIPFIXTypeHandlingMode::Number, 387));
		hm.insert(388, ("dot1qDEI", "", NetflowIPFIXTypeHandlingMode::Boolean, 388));
		hm.insert(389, ("dot1qCustomerDEI", "", NetflowIPFIXTypeHandlingMode::Boolean, 389));
		hm.insert(390, ("flowSelectorAlgorithm", "", NetflowIPFIXTypeHandlingMode::Number, 390));
		hm.insert(391, ("flowSelectedOctetDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 391));
		hm.insert(392, ("flowSelectedPacketDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 392));
		hm.insert(393, ("flowSelectedFlowDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 393));
		hm.insert(394, ("selectorIDTotalFlowsObserved", "", NetflowIPFIXTypeHandlingMode::Number, 394));
		hm.insert(395, ("selectorIDTotalFlowsSelected", "", NetflowIPFIXTypeHandlingMode::Number, 395));
		hm.insert(396, ("samplingFlowInterval", "", NetflowIPFIXTypeHandlingMode::Number, 396));
		hm.insert(397, ("samplingFlowSpacing", "", NetflowIPFIXTypeHandlingMode::Number, 397));
		hm.insert(398, ("flowSamplingTimeInterval", "", NetflowIPFIXTypeHandlingMode::Number, 398));
		hm.insert(399, ("flowSamplingTimeSpacing", "", NetflowIPFIXTypeHandlingMode::Number, 399));
		hm.insert(400, ("hashFlowDomain", "", NetflowIPFIXTypeHandlingMode::Number, 400));
		hm.insert(401, ("transportOctetDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 401));
		hm.insert(402, ("transportPacketDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 402));
		hm.insert(403, ("originalExporterIPv4Address", "", NetflowIPFIXTypeHandlingMode::IPv4, 403));
		hm.insert(404, ("originalExporterIPv6Address", "", NetflowIPFIXTypeHandlingMode::IPv6, 404));
		hm.insert(405, ("originalObservationDomainId", "", NetflowIPFIXTypeHandlingMode::Number, 405));
		hm.insert(406, ("intermediateProcessId", "", NetflowIPFIXTypeHandlingMode::Number, 406));
		hm.insert(407, ("ignoredDataRecordTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 407));
		hm.insert(408, ("dataLinkFrameType", "", NetflowIPFIXTypeHandlingMode::Number, 408));
		hm.insert(409, ("sectionOffset", "", NetflowIPFIXTypeHandlingMode::Number, 409));
		hm.insert(410, ("sectionExportedOctets", "", NetflowIPFIXTypeHandlingMode::Number, 410));
		hm.insert(411, ("dot1qServiceInstanceTag", "", NetflowIPFIXTypeHandlingMode::OctetArray, 411));
		hm.insert(412, ("dot1qServiceInstanceId", "", NetflowIPFIXTypeHandlingMode::Number, 412));
		hm.insert(413, ("dot1qServiceInstancePriority", "", NetflowIPFIXTypeHandlingMode::Number, 413));
		hm.insert(414, ("dot1qCustomerSourceMacAddress", "", NetflowIPFIXTypeHandlingMode::MAC, 414));
		hm.insert(415, ("dot1qCustomerDestinationMacAddress", "", NetflowIPFIXTypeHandlingMode::MAC, 415));
		hm.insert(416, ("layer2OctetDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 416));
		hm.insert(417, ("postLayer2OctetDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 417));
		hm.insert(418, ("postMCastLayer2OctetDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 418));
		hm.insert(419, ("layer2OctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 419));
		hm.insert(420, ("postLayer2OctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 420));
		hm.insert(421, ("postMCastLayer2OctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 421));
		hm.insert(422, ("minimumLayer2TotalLength", "", NetflowIPFIXTypeHandlingMode::Number, 422));
		hm.insert(423, ("maximumLayer2TotalLength", "", NetflowIPFIXTypeHandlingMode::Number, 423));
		hm.insert(424, ("droppedLayer2OctetDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 424));
		hm.insert(425, ("droppedLayer2OctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 425));
		hm.insert(426, ("ignoredLayer2OctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 426));
		hm.insert(427, ("notSentLayer2OctetTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 427));
		hm.insert(428, ("layer2OctetDeltaSumOfSquares", "", NetflowIPFIXTypeHandlingMode::Number, 428));
		hm.insert(429, ("layer2OctetTotalSumOfSquares", "", NetflowIPFIXTypeHandlingMode::Number, 429));
		hm.insert(430, ("layer2FrameDeltaCount", "", NetflowIPFIXTypeHandlingMode::Number, 430));
		hm.insert(431, ("layer2FrameTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 431));
		hm.insert(432, ("pseudoWireDestinationIPv4Address", "", NetflowIPFIXTypeHandlingMode::IPv4, 432));
		hm.insert(433, ("ignoredLayer2FrameTotalCount", "", NetflowIPFIXTypeHandlingMode::Number, 433));
		hm.insert(434, ("mibObjectValueInteger", "", NetflowIPFIXTypeHandlingMode::SignedNumber, 434));
		hm.insert(435, ("mibObjectValueOctetString", "", NetflowIPFIXTypeHandlingMode::OctetArray, 435));
		hm.insert(436, ("mibObjectValueOID", "", NetflowIPFIXTypeHandlingMode::OctetArray, 436));
		hm.insert(437, ("mibObjectValueBits", "", NetflowIPFIXTypeHandlingMode::OctetArray, 437));
		hm.insert(438, ("mibObjectValueIPAddress", "", NetflowIPFIXTypeHandlingMode::IPv4, 438));
		hm.insert(439, ("mibObjectValueCounter", "", NetflowIPFIXTypeHandlingMode::Number, 439));
		hm.insert(440, ("mibObjectValueGauge", "", NetflowIPFIXTypeHandlingMode::Number, 440));
		hm.insert(441, ("mibObjectValueTimeTicks", "", NetflowIPFIXTypeHandlingMode::Number, 441));
		hm.insert(442, ("mibObjectValueUnsigned", "", NetflowIPFIXTypeHandlingMode::Number, 442));
		hm.insert(443, ("mibObjectValueTable", "", NetflowIPFIXTypeHandlingMode::OctetArray, 443));
		hm.insert(444, ("mibObjectValueRow", "", NetflowIPFIXTypeHandlingMode::OctetArray, 444));
		hm.insert(445, ("mibObjectIdentifier", "", NetflowIPFIXTypeHandlingMode::OctetArray, 445));
		hm.insert(446, ("mibSubIdentifier", "", NetflowIPFIXTypeHandlingMode::Number, 446));
		hm.insert(447, ("mibIndexIndicator", "", NetflowIPFIXTypeHandlingMode::Number, 447));
		hm.insert(448, ("mibCaptureTimeSemantics", "", NetflowIPFIXTypeHandlingMode::Number, 448));
		hm.insert(449, ("mibContextEngineID", "", NetflowIPFIXTypeHandlingMode::OctetArray, 449));
		hm.insert(450, ("mibContextName", "", NetflowIPFIXTypeHandlingMode::String, 450));
		hm.insert(451, ("mibObjectName", "", NetflowIPFIXTypeHandlingMode::String, 451));
		hm.insert(452, ("mibObjectDescription", "", NetflowIPFIXTypeHandlingMode::String, 452));
		hm.insert(453, ("mibObjectSyntax", "", NetflowIPFIXTypeHandlingMode::String, 453));
		hm.insert(454, ("mibModuleName", "", NetflowIPFIXTypeHandlingMode::String, 454));
		hm.insert(455, ("mobileIMSI", "", NetflowIPFIXTypeHandlingMode::String, 455));
		hm.insert(456, ("mobileMSISDN", "", NetflowIPFIXTypeHandlingMode::String, 456));
		hm.insert(457, ("httpStatusCode", "", NetflowIPFIXTypeHandlingMode::Number, 457));
		hm.insert(458, ("sourceTransportPortsLimit", "", NetflowIPFIXTypeHandlingMode::Number, 458));
		hm.insert(459, ("httpRequestMethod", "", NetflowIPFIXTypeHandlingMode::String, 459));
		hm.insert(460, ("httpRequestHost", "", NetflowIPFIXTypeHandlingMode::String, 460));
		hm.insert(461, ("httpRequestTarget", "", NetflowIPFIXTypeHandlingMode::String, 461));
		hm.insert(462, ("httpMessageVersion", "", NetflowIPFIXTypeHandlingMode::String, 462));
		hm.insert(463, ("natInstanceID", "", NetflowIPFIXTypeHandlingMode::Number, 463));
		hm.insert(464, ("internalAddressRealm", "", NetflowIPFIXTypeHandlingMode::OctetArray, 464));
		hm.insert(465, ("externalAddressRealm", "", NetflowIPFIXTypeHandlingMode::OctetArray, 465));
		hm.insert(466, ("natQuotaExceededEvent", "", NetflowIPFIXTypeHandlingMode::Number, 466));
		hm.insert(467, ("natThresholdEvent", "", NetflowIPFIXTypeHandlingMode::Number, 467));
		hm.insert(468, ("httpUserAgent", "", NetflowIPFIXTypeHandlingMode::String, 468));
		hm.insert(469, ("httpContentType", "", NetflowIPFIXTypeHandlingMode::String, 469));
		hm.insert(470, ("httpReasonPhrase", "", NetflowIPFIXTypeHandlingMode::String, 470));
		hm.insert(471, ("maxSessionEntries", "", NetflowIPFIXTypeHandlingMode::Number, 471));
		hm.insert(472, ("maxBIBEntries", "", NetflowIPFIXTypeHandlingMode::Number, 472));
		hm.insert(473, ("maxEntriesPerUser", "", NetflowIPFIXTypeHandlingMode::Number, 473));
		hm.insert(474, ("maxSubscribers", "", NetflowIPFIXTypeHandlingMode::Number, 474));
		hm.insert(475, ("maxFragmentsPendingReassembly", "", NetflowIPFIXTypeHandlingMode::Number, 475));
		hm.insert(476, ("addressPoolHighThreshold", "", NetflowIPFIXTypeHandlingMode::Number, 476));
		hm.insert(477, ("addressPoolLowThreshold", "", NetflowIPFIXTypeHandlingMode::Number, 477));
		hm.insert(478, ("addressPortMappingHighThreshold", "", NetflowIPFIXTypeHandlingMode::Number, 478));
		hm.insert(479, ("addressPortMappingLowThreshold", "", NetflowIPFIXTypeHandlingMode::Number, 479));
		hm.insert(480, ("addressPortMappingPerUserHighThreshold", "", NetflowIPFIXTypeHandlingMode::Number, 480));
		hm.insert(481, ("globalAddressMappingHighThreshold", "", NetflowIPFIXTypeHandlingMode::Number, 481));
		hm.insert(482, ("vpnIdentifier", "", NetflowIPFIXTypeHandlingMode::OctetArray, 482));
		hm.insert(483, ("bgpCommunity", "", NetflowIPFIXTypeHandlingMode::Number, 483));
		hm.insert(484, ("bgpSourceCommunityList", "", NetflowIPFIXTypeHandlingMode::OctetArray, 484));
		hm.insert(485, ("bgpDestinationCommunityList", "", NetflowIPFIXTypeHandlingMode::OctetArray, 485));
		hm.insert(486, ("bgpExtendedCommunity", "", NetflowIPFIXTypeHandlingMode::OctetArray, 486));
		hm.insert(487, ("bgpSourceExtendedCommunityList", "", NetflowIPFIXTypeHandlingMode::OctetArray, 487));
		hm.insert(488, ("bgpDestinationExtendedCommunityList", "", NetflowIPFIXTypeHandlingMode::OctetArray, 488));
		hm.insert(489, ("bgpLargeCommunity", "", NetflowIPFIXTypeHandlingMode::OctetArray, 489));
		hm.insert(490, ("bgpSourceLargeCommunityList", "", NetflowIPFIXTypeHandlingMode::OctetArray, 490));
		hm.insert(491, ("bgpDestinationLargeCommunityList", "", NetflowIPFIXTypeHandlingMode::OctetArray, 491));


		hm
	};
}
