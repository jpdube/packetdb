pub const FRAME_BASE: u32 = 0x00000000;
pub const FRAME_TIMESTAMP: u32 = 0x00000001;
pub const FRAME_OFFSET: u32 = 0x00000002;
pub const FRAME_ORIG_LEN: u32 = 0x00000003;
pub const FRAME_INC_LEN: u32 = 0x00000004;
pub const FRAME_FILE_ID: u32 = 0x00000005;
pub const FRAME_PKT_PTR: u32 = 0x00000006;

//--- Ethernet
pub const ETH_BASE: u32 = 0x00010000;
pub const ETH_DST_MAC: u32 = 0x00010001;
pub const ETH_SRC_MAC: u32 = 0x00010002;
pub const ETH_PROTO: u32 = 0x00010003;
pub const ETH_VLAN_ID: u32 = 0x00010004;
pub const ETH_PACKET: u32 = 0x00010005;

//--- IP V4
pub const IPV4_BASE: u32 = 0x00020000;
pub const IPV4_DST_ADDR: u32 = 0x00020001;
pub const IPV4_SRC_ADDR: u32 = 0x00020002;
pub const IPV4_VERSION: u32 = 0x00020003;
pub const IPV4_HEADER_LEN: u32 = 0x00020004;
pub const IPV4_TOS: u32 = 0x00020005;
pub const IPV4_PROTOCOL: u32 = 0x00020006;
pub const IPV4_TTL: u32 = 0x00020007;

//--- UDP
pub const UDP_BASE: u32 = 0x00030000;
pub const UDP_SRC_PORT: u32 = 0x00030001;
pub const UDP_DEST_PORT: u32 = 0x00030002;
pub const UDP_LEN: u32 = 0x00030003;
pub const UDP_CHEKCSUM: u32 = 0x00030004;
pub const UDP_PACKET: u32 = 0x00030005;

//-- TCP
pub const TCP_BASE: u32 = 0x00040000;
pub const TCP_SRC_PORT: u32 = 0x00040001;
pub const TCP_DEST_PORT: u32 = 0x00040002;
pub const TCP_ACK_NO: u32 = 0x00040003;
pub const TCP_SEQ_NO: u32 = 0x00040004;
pub const TCP_FLAGS_ACK: u32 = 0x00040005;
pub const TCP_FLAGS_PUSH: u32 = 0x00040006;
pub const TCP_FLAGS_SYN: u32 = 0x00040007;
pub const TCP_FLAGS_RESET: u32 = 0x00040008;
pub const TCP_FLAGS_FIN: u32 = 0x00040009;
pub const TCP_FLAGS_URG: u32 = 0x0004000A;
pub const TCP_WIN_SIZE: u32 = 0x0004000B;
pub const TCP_HDR_LEN: u32 = 0x0004000C;
pub const TCP_PAYLOAD_LEN: u32 = 0x0004000D;
pub const TCP_OPTIONS_WIN_SCALE: u32 = 0x0004000E;
pub const TCP_OPTIONS_WIN_SCALE_MUL: u32 = 0x0004000F;
pub const TCP_OPTIONS_SACK: u32 = 0x00040010;
pub const TCP_OPTIONS_SACK_COUNT: u32 = 0x00040011;
pub const TCP_OPTIONS_SCALE_LE: u32 = 0x00040012;
pub const TCP_OPTIONS_SCALE_RE: u32 = 0x00040013;
pub const TCP_OPTIONS_MSS: u32 = 0x00040014;
pub const TCP_OPTIONS_TIMESTAMP: u32 = 0x00040015;
pub const TCP_OPTIONS_TIMESTAMP_TSVAL: u32 = 0x00040016;
pub const TCP_OPTIONS_TIMESTAMP_TSECR: u32 = 0x00040017;
pub const TCP_PACKET: u32 = 0x00040018;

//-- ICMP
pub const ICMP_BASE: u32 = 0x00050000;
pub const ICMP_TYPE: u32 = 0x00050001;
pub const ICMP_CODE: u32 = 0x00050002;
pub const ICMP_IDENTIFIER: u32 = 0x00050003;
pub const ICMP_SEQ_NO: u32 = 0x00050004;
pub const ICMP_PACKET: u32 = 0x00050005;

pub fn string_to_int(field_str: &str) -> Option<u32> {
    match field_str {
        //--- Frame
        "frame.timestamp" => Some(FRAME_TIMESTAMP),
        "frame.offset" => Some(FRAME_OFFSET),
        "frame.origlen" => Some(FRAME_ORIG_LEN),
        "frame.inclen" => Some(FRAME_INC_LEN),
        "frame.file_id" => Some(FRAME_FILE_ID),
        "frame.pkt_ptr" => Some(FRAME_PKT_PTR),

        //--- Ethernet
        "eth.src" => Some(ETH_SRC_MAC),
        "eth.dst" => Some(ETH_DST_MAC),
        "eth.type" => Some(ETH_PROTO),
        "eth.vlan" => Some(ETH_VLAN_ID),
        "eth.packet" => Some(ETH_PACKET),

        //--- IP version 4
        "ip.src" => Some(IPV4_SRC_ADDR),
        "ip.dst" => Some(IPV4_DST_ADDR),
        "ip.tos" => Some(IPV4_TOS),
        "ip.ttl" => Some(IPV4_TTL),
        "ip.protocol" => Some(IPV4_PROTOCOL),
        "ip.hdr_len" => Some(IPV4_HEADER_LEN),

        //--- UDP
        "udp.sport" => Some(UDP_SRC_PORT),
        "udp.dport" => Some(UDP_DEST_PORT),
        "udp.length" => Some(UDP_LEN),
        "udp.checksum" => Some(UDP_CHEKCSUM),
        "udp.packet" => Some(UDP_PACKET),

        //--- TCP
        "tcp.sport" => Some(TCP_SRC_PORT),
        "tcp.dport" => Some(TCP_DEST_PORT),
        "tcp.ackno" => Some(TCP_ACK_NO),
        "tcp.seqno" => Some(TCP_SEQ_NO),
        "tcp.flags.ack" => Some(TCP_FLAGS_ACK),
        "tcp.flags.push" => Some(TCP_FLAGS_PUSH),
        "tcp.flags.syn" => Some(TCP_FLAGS_SYN),
        "tcp.flags.reset" => Some(TCP_FLAGS_RESET),
        "tcp.flags.fin" => Some(TCP_FLAGS_FIN),
        "tcp.flags.urg" => Some(TCP_FLAGS_URG),
        "tcp.winsize" => Some(TCP_WIN_SIZE),
        "tcp.hdrlen" => Some(TCP_HDR_LEN),
        "tcp.payload.len" => Some(TCP_PAYLOAD_LEN),
        "tcp.options.wscale" => Some(TCP_OPTIONS_WIN_SCALE),
        "tcp.options.wscale.multiplier" => Some(TCP_OPTIONS_WIN_SCALE_MUL),
        "tcp.options.sack" => Some(TCP_OPTIONS_SACK),
        "tcp.options.sack.count" => Some(TCP_OPTIONS_SACK_COUNT),
        "tcp.options.sack.le" => Some(TCP_OPTIONS_SCALE_LE),
        "tcp.options.sack.re" => Some(TCP_OPTIONS_SCALE_RE),
        "tcp.options.mss" => Some(TCP_OPTIONS_MSS),
        "tcp.options.timestamp" => Some(TCP_OPTIONS_TIMESTAMP),
        "tcp.options.timestamp.tsval" => Some(TCP_OPTIONS_TIMESTAMP_TSVAL),
        "tcp.options.timestamp.tsecr" => Some(TCP_OPTIONS_TIMESTAMP_TSECR),
        "tcp.packet" => Some(TCP_PACKET),

        //--- ICMP
        "icmp.type" => Some(ICMP_TYPE),
        "icmp.code" => Some(ICMP_CODE),
        "icmp.identifier" => Some(ICMP_IDENTIFIER),
        "icmp.seq_no" => Some(ICMP_SEQ_NO),
        "icmp.packet" => Some(ICMP_PACKET),

        _ => None,
    }
}
