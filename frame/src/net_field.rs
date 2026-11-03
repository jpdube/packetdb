use phf::phf_map;

pub const SECTION_MASK: u32 = 0xFFFF_0000;

pub const FRAME_BASE: u32 = 0x0001_0000;
pub const FRAME_TIMESTAMP: u32 = FRAME_BASE | 0x0001;
pub const FRAME_OFFSET: u32 = FRAME_BASE | 0x0002;
pub const FRAME_ORIG_LEN: u32 = FRAME_BASE | 0x0003;
pub const FRAME_INC_LEN: u32 = FRAME_BASE | 0x0004;
pub const FRAME_FILE_ID: u32 = FRAME_BASE | 0x0005;
pub const FRAME_PKT_PTR: u32 = FRAME_BASE | 0x0006;
pub const FRAME_ID: u32 = FRAME_BASE | 0x0007;

//--- Ethernet
pub const ETH_BASE: u32 = 0x0002_0000;
pub const ETH_DST_MAC: u32 = ETH_BASE | 0x0001;
pub const ETH_SRC_MAC: u32 = ETH_BASE | 0x0002;
pub const ETH_PROTO: u32 = ETH_BASE | 0x0003;
pub const ETH_VLAN_ID: u32 = ETH_BASE | 0x0004;
pub const ETH_PACKET: u32 = ETH_BASE | 0x0005;
pub const ETH_HAS_ARP: u32 = ETH_BASE | 0x0006;
pub const ETH_HAS_IPV4: u32 = ETH_BASE | 0x0007;

//--- IP V4
pub const IPV4_BASE: u32 = 0x0004_0000;
pub const IPV4_DST_ADDR: u32 = IPV4_BASE | 0x0001;
pub const IPV4_SRC_ADDR: u32 = IPV4_BASE | 0x0002;
pub const IPV4_VERSION: u32 = IPV4_BASE | 0x0003;
pub const IPV4_HEADER_LEN: u32 = IPV4_BASE | 0x0004;
pub const IPV4_TOS: u32 = IPV4_BASE | 0x0005;
pub const IPV4_PROTOCOL: u32 = IPV4_BASE | 0x0006;
pub const IPV4_TTL: u32 = IPV4_BASE | 0x0007;
pub const IPV4_HAS_TCP: u32 = IPV4_BASE | 0x0008;
pub const IPV4_HAS_UDP: u32 = IPV4_BASE | 0x0009;
pub const IPV4_HAS_ICMP: u32 = IPV4_BASE | 0x000a;

//--- UDP
pub const UDP_BASE: u32 = 0x0008_0000;
pub const UDP_SRC_PORT: u32 = UDP_BASE | 0x0001;
pub const UDP_DEST_PORT: u32 = UDP_BASE | 0x0002;
pub const UDP_LEN: u32 = UDP_BASE | 0x0003;
pub const UDP_CHEKCSUM: u32 = UDP_BASE | 0x0004;
pub const UDP_PACKET: u32 = UDP_BASE | 0x0005;
pub const UDP_HAS_DNS: u32 = UDP_BASE | 0x0006;
pub const UDP_HAS_DHCP: u32 = UDP_BASE | 0x0007;
pub const UDP_HAS_NTP: u32 = UDP_BASE | 0x0008;
pub const UDP_HAS_SNMP: u32 = UDP_BASE | 0x0009;

//-- TCP
pub const TCP_BASE: u32 = 0x0010_0000;
pub const TCP_SRC_PORT: u32 = TCP_BASE | 0x0001;
pub const TCP_DEST_PORT: u32 = TCP_BASE | 0x0002;
pub const TCP_ACK_NO: u32 = TCP_BASE | 0x0003;
pub const TCP_SEQ_NO: u32 = TCP_BASE | 0x0004;
pub const TCP_FLAGS_ACK: u32 = TCP_BASE | 0x0005;
pub const TCP_FLAGS_PUSH: u32 = TCP_BASE | 0x0006;
pub const TCP_FLAGS_SYN: u32 = TCP_BASE | 0x0007;
pub const TCP_FLAGS_RESET: u32 = TCP_BASE | 0x0008;
pub const TCP_FLAGS_FIN: u32 = TCP_BASE | 0x0009;
pub const TCP_FLAGS_URG: u32 = TCP_BASE | 0x000A;
pub const TCP_WIN_SIZE: u32 = TCP_BASE | 0x000B;
pub const TCP_HDR_LEN: u32 = TCP_BASE | 0x000C;
pub const TCP_PAYLOAD_LEN: u32 = TCP_BASE | 0x000D;
pub const TCP_OPTIONS_WIN_SCALE: u32 = TCP_BASE | 0xf000E;
pub const TCP_OPTIONS_WIN_SCALE_MUL: u32 = TCP_BASE | 0x000F;
pub const TCP_OPTIONS_SACK: u32 = TCP_BASE | 0x0010;
pub const TCP_OPTIONS_SACK_COUNT: u32 = TCP_BASE | 0x0011;
pub const TCP_OPTIONS_SCALE_LE: u32 = TCP_BASE | 0x0012;
pub const TCP_OPTIONS_SCALE_RE: u32 = TCP_BASE | 0x0013;
pub const TCP_OPTIONS_MSS: u32 = TCP_BASE | 0x0014;
pub const TCP_OPTIONS_TIMESTAMP: u32 = TCP_BASE | 0x0015;
pub const TCP_OPTIONS_TIMESTAMP_TSVAL: u32 = TCP_BASE | 0x0016;
pub const TCP_OPTIONS_TIMESTAMP_TSECR: u32 = TCP_BASE | 0x0017;
pub const TCP_PACKET: u32 = TCP_BASE | 0x0018;
pub const TCP_PROTO_NAME: u32 = TCP_BASE | 0x0019;

//-- ICMP
pub const ICMP_BASE: u32 = 0x0020_0000;
pub const ICMP_TYPE: u32 = ICMP_BASE | 0x0001;
pub const ICMP_CODE: u32 = ICMP_BASE | 0x0002;
pub const ICMP_IDENTIFIER: u32 = ICMP_BASE | 0x0003;
pub const ICMP_SEQ_NO: u32 = ICMP_BASE | 0x0004;
pub const ICMP_PACKET: u32 = ICMP_BASE | 0x0005;

//-- ARP
pub const ARP_BASE: u32 = 0x0040_0000;
pub const ARP_SHA: u32 = ARP_BASE | 0x0001;
pub const ARP_SPA: u32 = ARP_BASE | 0x0002;
pub const ARP_THA: u32 = ARP_BASE | 0x0003;
pub const ARP_TPA: u32 = ARP_BASE | 0x0004;
pub const ARP_HTYPE: u32 = ARP_BASE | 0x0005;
pub const ARP_PTYPE: u32 = ARP_BASE | 0x0006;
pub const ARP_OPCODE: u32 = ARP_BASE | 0x0007;
pub const ARP_HLEN: u32 = ARP_BASE | 0x0008;
pub const ARP_PLEN: u32 = ARP_BASE | 0x0009;

//-- DNS
pub const DNS_BASE: u32 = 0x0080_0000;
pub const DNS_ID: u32 = DNS_BASE | 0x0001;
pub const DNS_IS_QUERY: u32 = DNS_BASE | 0x0002;
pub const DNS_IS_RESPONSE: u32 = DNS_BASE | 0x0003;
pub const DNS_OPCODE: u32 = DNS_BASE | 0x0004;
pub const DNS_QUESTION_COUNT: u32 = DNS_BASE | 0x0005;
pub const DNS_ANSWER_COUNT: u32 = DNS_BASE | 0x0006;
pub const DNS_AUTHORITY_COUNT: u32 = DNS_BASE | 0x0007;
pub const DNS_IS_AUTHORITATIVE: u32 = DNS_BASE | 0x0008;
pub const DNS_REPLY_CODE: u32 = DNS_BASE | 0x0009;
pub const DNS_ANSWERS: u32 = DNS_BASE | 0x000A;
pub const DNS_HAS_RRSIG: u32 = DNS_BASE | 0x000B;
pub const DNS_HAS_AAAA: u32 = DNS_BASE | 0x000C;
pub const DNS_TYPE_AAAA: u32 = DNS_BASE | 0x000D;
pub const DNS_TYPE_A: u32 = DNS_BASE | 0x000E;

//--- DHCP
pub const DHCP_BASE: u32 = 0x0100_0000;
pub const DHCP_OPCODE: u32 = DHCP_BASE | 0x0001;
pub const DHCP_HWND_TYPE: u32 = DHCP_BASE | 0x0002;
pub const DHCP_HWND_LEN: u32 = DHCP_BASE | 0x0003;
pub const DHCP_HOPS: u32 = DHCP_BASE | 0x0004;
pub const DHCP_XID: u32 = DHCP_BASE | 0x0005;
pub const DHCP_SECS: u32 = DHCP_BASE | 0x0006;
pub const DHCP_FLAGS: u32 = DHCP_BASE | 0x0007;
pub const DHCP_CLIENT_IP: u32 = DHCP_BASE | 0x0008;
pub const DHCP_YOUR_IP: u32 = DHCP_BASE | 0x0009;
pub const DHCP_NEXT_SRV_IP: u32 = DHCP_BASE | 0x000A;
pub const DHCP_RELAY_AGENT_IP: u32 = DHCP_BASE | 0x000B;
pub const DHCP_CLIENT_MAC: u32 = DHCP_BASE | 0x000C;
pub const DHCP_SRV_NAME: u32 = DHCP_BASE | 0x000D;
pub const DHCP_FILENAME: u32 = DHCP_BASE | 0x000E;
pub const DHCP_DOMAIN_NAME: u32 = DHCP_BASE | 0x000F;
pub const DHCP_IP_LEASE_TIME: u32 = DHCP_BASE | 0x0010;
pub const DHCP_DOMAIN_SRV: u32 = DHCP_BASE | 0x0011;
pub const DHCP_REBINDING_TIME: u32 = DHCP_BASE | 0x0012;
pub const DHCP_RENEWAL_TIME: u32 = DHCP_BASE | 0x0013;
pub const DHCP_ROUTER: u32 = DHCP_BASE | 0x0014;
pub const DHCP_SUBNET_MASK: u32 = DHCP_BASE | 0x0015;
pub const DHCP_SERVER_ID: u32 = DHCP_BASE | 0x0016;
pub const DHCP_REQUESTED_IP: u32 = DHCP_BASE | 0x0017;
pub const DHCP_CLIENT_ID_HWND_TYPE: u32 = DHCP_BASE | 0x0018;
pub const DHCP_CLIENT_ID_MAC: u32 = DHCP_BASE | 0x0019;
pub const DHCP_HOSTNAME: u32 = DHCP_BASE | 0x001A;
pub const DHCP_CLIENT_FQDN_FLAGS: u32 = DHCP_BASE | 0x001B;
pub const DHCP_CLIENT_FQDN_A_RESULT: u32 = DHCP_BASE | 0x001C;
pub const DHCP_CLIENT_FQDN_PTR_RESULT: u32 = DHCP_BASE | 0x001D;
pub const DHCP_CLIENT_FQDN_NAME: u32 = DHCP_BASE | 0x001E;
pub const DHCP_VENDOR_CLASS_ID: u32 = DHCP_BASE | 0x001F;
pub const DHCP_VENDOR_INFO: u32 = DHCP_BASE | 0x0020;
pub const DHCP_PARAMS_REQ_LIST: u32 = DHCP_BASE | 0x0021;

pub const NTP_BASE: u32 = 0x0200_0000;
pub const NTP_LEAP_INDICATOR: u32 = NTP_BASE | 0x0001;
pub const NTP_VERSION_NO: u32 = NTP_BASE | 0x0002;
pub const NTP_MODE: u32 = NTP_BASE | 0x0003;
pub const NTP_STRATUM: u32 = NTP_BASE | 0x0004;
pub const NTP_POLL: u32 = NTP_BASE | 0x0005;
pub const NTP_PRECISION: u32 = NTP_BASE | 0x0006;
pub const NTP_ROOT_DELAY: u32 = NTP_BASE | 0x0007;
pub const NTP_ROOT_DISPERSION: u32 = NTP_BASE | 0x0008;
pub const NTP_REF_ID: u32 = NTP_BASE | 0x0009;
pub const NTP_REF_TIMESTAMP: u32 = NTP_BASE | 0x000A;
pub const NTP_ORIGIN_TIMESTAMP: u32 = NTP_BASE | 0x000B;
pub const NTP_RECV_TIMESTAMP: u32 = NTP_BASE | 0x000C;
pub const NTP_XMIT_TIMESTAMP: u32 = NTP_BASE | 0x000D;
pub const NTP_OPT_EXTENSION: u32 = NTP_BASE | 0x000E;
pub const NTP_KEY_ID: u32 = NTP_BASE | 0x000F;
pub const NTP_MSG_DIGEST: u32 = NTP_BASE | 0x0010;
pub const NTP_MODE_LABEL: u32 = NTP_BASE | 0x0011;

pub const SIP_BASE: u32 = 0x0400_0000;
pub const SIP_METHOD: u32 = SIP_BASE | 0x0001;
pub const SIP_REQUEST_URI: u32 = SIP_BASE | 0x0002;
pub const SIP_VERSION: u32 = SIP_BASE | 0x0003;

pub fn string_to_int(field: &str) -> Option<u32> {
    NET_CONSTANT.get(field).copied()
}

static NET_CONSTANT: phf::Map<&'static str, u32> = phf_map! {
    //--- Frame
    "frame.timestamp" => FRAME_TIMESTAMP,
    "frame.offset" => FRAME_OFFSET,
    "frame.origlen" => FRAME_ORIG_LEN,
    "frame.inclen" => FRAME_INC_LEN,
    "frame.file_id" => FRAME_FILE_ID,
    "frame.pkt_ptr" => FRAME_PKT_PTR,
    "frame.id" => FRAME_ID,

    //--- Ethernet
    "eth.src" => ETH_SRC_MAC,
    "eth.dst" => ETH_DST_MAC,
    "eth.type" => ETH_PROTO,
    "eth.vlan" => ETH_VLAN_ID,
    "eth.packet" => ETH_PACKET,
    "eth.has_arp" => ETH_HAS_ARP,
    "eth.has_ipv4" => ETH_HAS_IPV4,

    //--- IP version 4
    "ip.src" => IPV4_SRC_ADDR,
    "ip.dst" => IPV4_DST_ADDR,
    "ip.tos" => IPV4_TOS,
    "ip.ttl" => IPV4_TTL,
    "ip.protocol" => IPV4_PROTOCOL,
    "ip.hdr_len" => IPV4_HEADER_LEN,
    "ip.has_tcp" => IPV4_HAS_TCP,
    "ip.has_udp" => IPV4_HAS_UDP,
    "ip.has_icmp" => IPV4_HAS_ICMP,

    //--- UDP
    "udp.sport" => UDP_SRC_PORT,
    "udp.dport" => UDP_DEST_PORT,
    "udp.length" => UDP_LEN,
    "udp.checksum" => UDP_CHEKCSUM,
    "udp.packet" => UDP_PACKET,
    "udp.has_dns" => UDP_HAS_DNS,
    "udp.has_dhcp" => UDP_HAS_DHCP,
    "udp.has_ntp" => UDP_HAS_NTP,
    "udp.has_snmp" => UDP_HAS_SNMP,

    //--- TCP
    "tcp.sport" => TCP_SRC_PORT,
    "tcp.dport" => TCP_DEST_PORT,
    "tcp.ackno" => TCP_ACK_NO,
    "tcp.seqno" => TCP_SEQ_NO,
    "tcp.flags_ack" => TCP_FLAGS_ACK,
    "tcp.flags_push" => TCP_FLAGS_PUSH,
    "tcp.flags_syn" => TCP_FLAGS_SYN,
    "tcp.flags_reset" => TCP_FLAGS_RESET,
    "tcp.flags_fin" => TCP_FLAGS_FIN,
    "tcp.flags_urg" => TCP_FLAGS_URG,
    "tcp.winsize" => TCP_WIN_SIZE,
    "tcp.hdrlen" => TCP_HDR_LEN,
    "tcp.payload_len" => TCP_PAYLOAD_LEN,
    "tcp.options_wscale" => TCP_OPTIONS_WIN_SCALE,
    "tcp.options_wscale.multiplier" => TCP_OPTIONS_WIN_SCALE_MUL,
    "tcp.options_sack" => TCP_OPTIONS_SACK,
    "tcp.options_sack.count" => TCP_OPTIONS_SACK_COUNT,
    "tcp.options_sack.le" => TCP_OPTIONS_SCALE_LE,
    "tcp.options_sack.re" => TCP_OPTIONS_SCALE_RE,
    "tcp.options_mss" => TCP_OPTIONS_MSS,
    "tcp.options_timestamp" => TCP_OPTIONS_TIMESTAMP,
    "tcp.options_timestamp.tsval" => TCP_OPTIONS_TIMESTAMP_TSVAL,
    "tcp.options_timestamp.tsecr" => TCP_OPTIONS_TIMESTAMP_TSECR,
    "tcp.packet" => TCP_PACKET,
    "tcp.proto_name" => TCP_PROTO_NAME,

    //--- ARP
    "arp.sender_mac" => ARP_SHA,
    "arp.sender_ip" => ARP_SPA,
    "arp.target_mac" => ARP_THA,
    "arp.target_ip" => ARP_TPA,
    "arp.hwd_type" => ARP_HTYPE,
    "arp.proto_type" => ARP_PTYPE,
    "arp.opcode" => ARP_OPCODE,
    "arp.proto_size" => ARP_PLEN,
    "arp.hwd_size" => ARP_HLEN,

    //--- ICMP
    "icmp.type" => ICMP_TYPE,
    "icmp.code" => ICMP_CODE,
    "icmp.identifier" => ICMP_IDENTIFIER,
    "icmp.seq_no" => ICMP_SEQ_NO,
    "icmp.packet" => ICMP_PACKET,

    //--- DNS
    "dns.id" => DNS_ID,
    "dns.opcode" => DNS_OPCODE,
    "dns.answer_count" => DNS_ANSWER_COUNT,
    "dns.question_count" => DNS_QUESTION_COUNT,
    "dns.answers" => DNS_ANSWERS,
    "dns.has_rrsig" => DNS_HAS_RRSIG,
    "dns.has_aaaa" => DNS_HAS_AAAA,
    "dns.type_aaaa" => DNS_TYPE_AAAA,
    "dns.type_a" => DNS_TYPE_A,

    //--- DHCP
    "dhcp.xid" => DHCP_XID,
    "dhcp.client_ip" => DHCP_CLIENT_IP,
    "dhcp.opcode" => DHCP_OPCODE,
    "dhcp.domain_name" => DHCP_DOMAIN_NAME,
    "dhcp.ip_lease_time" => DHCP_IP_LEASE_TIME,
    "dhcp.domain_srv" => DHCP_DOMAIN_SRV,
    "dhcp.renewal_time" => DHCP_RENEWAL_TIME,
    "dhcp.rebinding_time" => DHCP_REBINDING_TIME,
    "dhcp.router" => DHCP_ROUTER,
    "dhcp.subnet_mask" => DHCP_SUBNET_MASK,
    "dhcp.server_id" => DHCP_SERVER_ID,
    "dhcp.requested_ip" => DHCP_REQUESTED_IP,
    "dhcp.client_hwnd_type" => DHCP_CLIENT_ID_HWND_TYPE,
    "dhcp.client_mac" => DHCP_CLIENT_ID_MAC,
    "dhcp.hostname" => DHCP_HOSTNAME,
    "dhcp.client_fqdn_flags" => DHCP_CLIENT_FQDN_FLAGS,
    "dhcp.client_fqdn_a_result" => DHCP_CLIENT_FQDN_A_RESULT,
    "dhcp.client_fqdn_ptr_result" => DHCP_CLIENT_FQDN_PTR_RESULT,
    "dhcp.client_fqdn_name" => DHCP_CLIENT_FQDN_NAME,
    "dhcp.vendor_id" => DHCP_VENDOR_CLASS_ID,
    "dhcp.vendor_info" => DHCP_VENDOR_INFO,
    "dhcp.params_req_list" => DHCP_PARAMS_REQ_LIST,

    "ntp.leap_indicator" => NTP_LEAP_INDICATOR,
    "ntp.version" => NTP_VERSION_NO,
    "ntp.mode" => NTP_MODE,
    "ntp.stratum" => NTP_STRATUM,
    "ntp.poll" => NTP_POLL,
    "ntp.precision" => NTP_PRECISION,
    "ntp.root_delay" => NTP_ROOT_DELAY,
    "ntp.root_dispersion" => NTP_ROOT_DISPERSION,
    "ntp.ref_id" => NTP_REF_ID,
    "ntp.ref_timestamp" => NTP_REF_TIMESTAMP,
    "ntp.origin_timestamp" => NTP_ORIGIN_TIMESTAMP,
    "ntp.recv_timestamp" => NTP_RECV_TIMESTAMP,
    "ntp.xmit_timestamp" => NTP_XMIT_TIMESTAMP,
    "ntp.opt_extension" => NTP_OPT_EXTENSION,
    "ntp.key_id" => NTP_KEY_ID,
    "ntp.msg_digest" => NTP_MSG_DIGEST,
    "ntp.mode_label" => NTP_MODE_LABEL,

    "sip.method" => SIP_METHOD,
    "sip.request_uri" => SIP_REQUEST_URI,
    "sip.version" => SIP_VERSION,

    // _ => None,
};

// pub fn string_to_int(field_str: &str) -> Option<u32> {
//     match field_str {
//         //--- Frame
//         "frame.timestamp" => Some(FRAME_TIMESTAMP),
//         "frame.offset" => Some(FRAME_OFFSET),
//         "frame.origlen" => Some(FRAME_ORIG_LEN),
//         "frame.inclen" => Some(FRAME_INC_LEN),
//         "frame.file_id" => Some(FRAME_FILE_ID),
//         "frame.pkt_ptr" => Some(FRAME_PKT_PTR),
//         "frame.id" => Some(FRAME_ID),

//         //--- Ethernet
//         "eth.src" => Some(ETH_SRC_MAC),
//         "eth.dst" => Some(ETH_DST_MAC),
//         "eth.type" => Some(ETH_PROTO),
//         "eth.vlan" => Some(ETH_VLAN_ID),
//         "eth.packet" => Some(ETH_PACKET),
//         "eth.has_arp" => Some(ETH_HAS_ARP),
//         "eth.has_ipv4" => Some(ETH_HAS_IPV4),

//         //--- IP version 4
//         "ip.src" => Some(IPV4_SRC_ADDR),
//         "ip.dst" => Some(IPV4_DST_ADDR),
//         "ip.tos" => Some(IPV4_TOS),
//         "ip.ttl" => Some(IPV4_TTL),
//         "ip.protocol" => Some(IPV4_PROTOCOL),
//         "ip.hdr_len" => Some(IPV4_HEADER_LEN),
//         "ip.has_tcp" => Some(IPV4_HAS_TCP),
//         "ip.has_udp" => Some(IPV4_HAS_UDP),
//         "ip.has_icmp" => Some(IPV4_HAS_ICMP),

//         //--- UDP
//         "udp.sport" => Some(UDP_SRC_PORT),
//         "udp.dport" => Some(UDP_DEST_PORT),
//         "udp.length" => Some(UDP_LEN),
//         "udp.checksum" => Some(UDP_CHEKCSUM),
//         "udp.packet" => Some(UDP_PACKET),
//         "udp.has_dns" => Some(UDP_HAS_DNS),
//         "udp.has_dhcp" => Some(UDP_HAS_DHCP),
//         "udp.has_ntp" => Some(UDP_HAS_NTP),
//         "udp.has_snmp" => Some(UDP_HAS_SNMP),

//         //--- TCP
//         "tcp.sport" => Some(TCP_SRC_PORT),
//         "tcp.dport" => Some(TCP_DEST_PORT),
//         "tcp.ackno" => Some(TCP_ACK_NO),
//         "tcp.seqno" => Some(TCP_SEQ_NO),
//         "tcp.flags_ack" => Some(TCP_FLAGS_ACK),
//         "tcp.flags_push" => Some(TCP_FLAGS_PUSH),
//         "tcp.flags_syn" => Some(TCP_FLAGS_SYN),
//         "tcp.flags_reset" => Some(TCP_FLAGS_RESET),
//         "tcp.flags_fin" => Some(TCP_FLAGS_FIN),
//         "tcp.flags_urg" => Some(TCP_FLAGS_URG),
//         "tcp.winsize" => Some(TCP_WIN_SIZE),
//         "tcp.hdrlen" => Some(TCP_HDR_LEN),
//         "tcp.payload_len" => Some(TCP_PAYLOAD_LEN),
//         "tcp.options_wscale" => Some(TCP_OPTIONS_WIN_SCALE),
//         "tcp.options_wscale.multiplier" => Some(TCP_OPTIONS_WIN_SCALE_MUL),
//         "tcp.options_sack" => Some(TCP_OPTIONS_SACK),
//         "tcp.options_sack.count" => Some(TCP_OPTIONS_SACK_COUNT),
//         "tcp.options_sack.le" => Some(TCP_OPTIONS_SCALE_LE),
//         "tcp.options_sack.re" => Some(TCP_OPTIONS_SCALE_RE),
//         "tcp.options_mss" => Some(TCP_OPTIONS_MSS),
//         "tcp.options_timestamp" => Some(TCP_OPTIONS_TIMESTAMP),
//         "tcp.options_timestamp.tsval" => Some(TCP_OPTIONS_TIMESTAMP_TSVAL),
//         "tcp.options_timestamp.tsecr" => Some(TCP_OPTIONS_TIMESTAMP_TSECR),
//         "tcp.packet" => Some(TCP_PACKET),
//         "tcp.proto_name" => Some(TCP_PROTO_NAME),

//         //--- ARP
//         "arp.sender_mac" => Some(ARP_SHA),
//         "arp.sender_ip" => Some(ARP_SPA),
//         "arp.target_mac" => Some(ARP_THA),
//         "arp.target_ip" => Some(ARP_TPA),
//         "arp.hwd_type" => Some(ARP_HTYPE),
//         "arp.proto_type" => Some(ARP_PTYPE),
//         "arp.opcode" => Some(ARP_OPCODE),
//         "arp.proto_size" => Some(ARP_PLEN),
//         "arp.hwd_size" => Some(ARP_HLEN),

//         //--- ICMP
//         "icmp.type" => Some(ICMP_TYPE),
//         "icmp.code" => Some(ICMP_CODE),
//         "icmp.identifier" => Some(ICMP_IDENTIFIER),
//         "icmp.seq_no" => Some(ICMP_SEQ_NO),
//         "icmp.packet" => Some(ICMP_PACKET),

//         //--- DNS
//         "dns.id" => Some(DNS_ID),
//         "dns.opcode" => Some(DNS_OPCODE),
//         "dns.answer_count" => Some(DNS_ANSWER_COUNT),
//         "dns.question_count" => Some(DNS_QUESTION_COUNT),
//         "dns.answers" => Some(DNS_ANSWERS),
//         "dns.has_rrsig" => Some(DNS_HAS_RRSIG),
//         "dns.has_aaaa" => Some(DNS_HAS_AAAA),
//         "dns.type_aaaa" => Some(DNS_TYPE_AAAA),
//         "dns.type_a" => Some(DNS_TYPE_A),

//         //--- DHCP
//         "dhcp.xid" => Some(DHCP_XID),
//         "dhcp.client_ip" => Some(DHCP_CLIENT_IP),
//         "dhcp.opcode" => Some(DHCP_OPCODE),
//         "dhcp.domain_name" => Some(DHCP_DOMAIN_NAME),
//         "dhcp.ip_lease_time" => Some(DHCP_IP_LEASE_TIME),
//         "dhcp.domain_srv" => Some(DHCP_DOMAIN_SRV),
//         "dhcp.renewal_time" => Some(DHCP_RENEWAL_TIME),
//         "dhcp.rebinding_time" => Some(DHCP_REBINDING_TIME),
//         "dhcp.router" => Some(DHCP_ROUTER),
//         "dhcp.subnet_mask" => Some(DHCP_SUBNET_MASK),
//         "dhcp.server_id" => Some(DHCP_SERVER_ID),
//         "dhcp.requested_ip" => Some(DHCP_REQUESTED_IP),
//         "dhcp.client_hwnd_type" => Some(DHCP_CLIENT_ID_HWND_TYPE),
//         "dhcp.client_mac" => Some(DHCP_CLIENT_ID_MAC),
//         "dhcp.hostname" => Some(DHCP_HOSTNAME),
//         "dhcp.client_fqdn_flags" => Some(DHCP_CLIENT_FQDN_FLAGS),
//         "dhcp.client_fqdn_a_result" => Some(DHCP_CLIENT_FQDN_A_RESULT),
//         "dhcp.client_fqdn_ptr_result" => Some(DHCP_CLIENT_FQDN_PTR_RESULT),
//         "dhcp.client_fqdn_name" => Some(DHCP_CLIENT_FQDN_NAME),
//         "dhcp.vendor_id" => Some(DHCP_VENDOR_CLASS_ID),
//         "dhcp.vendor_info" => Some(DHCP_VENDOR_INFO),
//         "dhcp.params_req_list" => Some(DHCP_PARAMS_REQ_LIST),

//         "ntp.leap_indicator" => Some(NTP_LEAP_INDICATOR),
//         "ntp.version" => Some(NTP_VERSION_NO),
//         "ntp.mode" => Some(NTP_MODE),
//         "ntp.stratum" => Some(NTP_STRATUM),
//         "ntp.poll" => Some(NTP_POLL),
//         "ntp.precision" => Some(NTP_PRECISION),
//         "ntp.root_delay" => Some(NTP_ROOT_DELAY),
//         "ntp.root_dispersion" => Some(NTP_ROOT_DISPERSION),
//         "ntp.ref_id" => Some(NTP_REF_ID),
//         "ntp.ref_timestamp" => Some(NTP_REF_TIMESTAMP),
//         "ntp.origin_timestamp" => Some(NTP_ORIGIN_TIMESTAMP),
//         "ntp.recv_timestamp" => Some(NTP_RECV_TIMESTAMP),
//         "ntp.xmit_timestamp" => Some(NTP_XMIT_TIMESTAMP),
//         "ntp.opt_extension" => Some(NTP_OPT_EXTENSION),
//         "ntp.key_id" => Some(NTP_KEY_ID),
//         "ntp.msg_digest" => Some(NTP_MSG_DIGEST),
//         "ntp.mode_label" => Some(NTP_MODE_LABEL),

//         "sip.method" => Some(SIP_METHOD),
//         "sip.request_uri" => Some(SIP_REQUEST_URI),
//         "sip.version" => Some(SIP_VERSION),

//         _ => None,
//     }
// }

pub fn build_fields_list() -> Vec<&'static str> {
    let field_list: Vec<&str> = vec![
        //--- Frame
        "frame.timestamp",
        "frame.offset",
        "frame.origlen",
        "frame.inclen",
        "frame.file_id",
        "frame.pkt_ptr",
        "frame.id",
        //--- Ethernet
        "eth.src",
        "eth.dst",
        "eth.type",
        "eth.vlan",
        "eth.packet",
        //--- ARP
        "arp.sender_mac",
        "arp.sender_ip",
        "arp.target_mac",
        "arp.target_ip",
        "arp.hwd_type",
        "arp.proto_type",
        "arp.opcode",
        "arp.proto_size",
        "arp.hwd_size",
        //--- IP version 4
        "ip.src",
        "ip.dst",
        "ip.tos",
        "ip.ttl",
        "ip.protocol",
        "ip.hdr_len",
        //--- UDP
        "udp.sport",
        "udp.dport",
        "udp.length",
        "udp.checksum",
        "udp.packet",
        //--- TCP
        "tcp.sport",
        "tcp.dport",
        "tcp.ackno",
        "tcp.seqno",
        "tcp.flags_ack",
        "tcp.flags_push",
        "tcp.flags_syn",
        "tcp.flags_reset",
        "tcp.flags_fin",
        "tcp.flags_urg",
        "tcp.winsize",
        "tcp.hdrlen",
        "tcp.payload_len",
        "tcp.options_wscale",
        "tcp.options_wscale.multiplier",
        "tcp.options_sack",
        "tcp.options_sack.count",
        "tcp.options_sack.le",
        "tcp.options_sack.re",
        "tcp.options_mss",
        "tcp.options_timestamp",
        "tcp.options_timestamp.tsval",
        "tcp.options_timestamp.tsecr",
        "tcp.packet",
        "tcp.proto_name",
        //--- ICMP
        "icmp.type",
        "icmp.code",
        "icmp.identifier",
        "icmp.seq_no",
        "icmp.packet",
        //--- DNS
        "dns.id",
        "dns.opcode",
        "dns.answer_count",
        "dns.question_count",
        "dns.answers",
        "dns.has_rrsig",
        "dns.has_aaaa",
        "dns.type_aaaa",
        "dns.type_a",
        //--- DHCP
        "dhcp.xid",
        "dhcp.client_ip",
        "dhcp.opcode",
        "dhcp.domain_name",
        "dhcp.ip_lease_time",
        "dhcp.domain_srv",
        "dhcp.renewal_time",
        "dhcp.rebinding_time",
        "dhcp.router",
        "dhcp.subnet_mask",
        "dhcp.server_id",
        "dhcp.requested_ip",
        "dhcp.client_hwnd_type",
        "dhcp.client_mac",
        "dhcp.hostname",
        "dhcp.client_fqdn_flags",
        "dhcp.client_fqdn_a_result",
        "dhcp.client_fqdn_ptr_result",
        "dhcp.client_fqdn_name",
        "dhcp.vendor_id",
        "dhcp.vendor_info",
        "dhcp.params_req_list",
        //--- NTP
        "ntp.leap_indicator",
        "ntp.version",
        "ntp.mode",
        "ntp.stratum",
        "ntp.poll",
        "ntp.precision",
        "ntp.root_delay",
        "ntp.root_dispersion",
        "ntp.ref_id",
        "ntp.ref_timestamp",
        "ntp.origin_timestamp",
        "ntp.recv_timestamp",
        "ntp.xmit_timestamp",
        "ntp.opt_extension",
        "ntp.key_id",
        "ntp.msg_digest",
        "ntp.mode_label",
    ];

    field_list
}

pub fn is_field_valid(field: &str) -> bool {
    let fields_list = build_fields_list();

    fields_list.contains(&field)
}
