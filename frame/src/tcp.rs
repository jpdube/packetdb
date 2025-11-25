use crate::layer::Layer;
use crate::packet_display::PacketDisplay;

use byteorder::{BigEndian, ByteOrder};
use field::pfield::{Field, FieldType};

const OPTION_EOL: u16 = 0;
const OPTION_NOP: u16 = 1;
const OPTION_MSS: u16 = 2;
const OPTION_WINSCALE: u16 = 3;
const OPTION_SACK: u16 = 4;
const OPTION_SACK_OPT: u16 = 5;
const OPTION_TIMESTAMP: u16 = 8;

#[derive(Debug, Default, Clone)]
pub struct SackOpt {
    left: u32,
    right: u32,
}

#[derive(Debug, Default, Clone)]
pub struct Timestamp {
    tsval: u32,
    tsecr: u32,
}

#[derive(Debug, Default, Clone)]
pub struct Options {
    sack_list: Vec<SackOpt>,
    timestamp: Timestamp,
    mss: u16,
    sack: bool,
    winscale: u8,
    win_multiplier: u16,
}

#[derive(Default, Debug, Clone)]
pub struct Tcp<'a> {
    raw_packet: &'a [u8],
    options: Options,
}

impl<'a> Tcp<'a> {
    pub fn new(packet: &'a [u8]) -> Self {
        let mut slf = Self {
            raw_packet: packet,
            options: Options::default(),
        };

        slf.decode_options();

        slf
    }

    pub fn seq_no(&self) -> u32 {
        BigEndian::read_u32(&self.raw_packet[4..8])
    }

    pub fn ack_no(&self) -> u32 {
        BigEndian::read_u32(&self.raw_packet[8..12])
    }

    pub fn flag(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[12..14])
    }

    pub fn flag_syn(&self) -> bool {
        self.flag() & 0x02 == 0x02
    }

    pub fn flag_ack(&self) -> bool {
        self.flag() & 0x10 == 0x10
    }

    pub fn flag_push(&self) -> bool {
        self.flag() & 0x08 == 0x08
    }

    pub fn flag_fin(&self) -> bool {
        self.flag() & 0x01 == 0x01
    }

    pub fn flag_urg(&self) -> bool {
        self.flag() & 0x20 == 0x20
    }

    pub fn flag_rst(&self) -> bool {
        self.flag() & 0x04 == 0x04
    }

    pub fn hdr_len(&self) -> u8 {
        let hdr_field = self.raw_packet[12];
        hdr_field >> 4
    }

    pub fn win_size(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[14..16])
    }

    pub fn payload_len(&self) -> u16 {
        self.raw_packet[(self.hdr_len() * 4) as usize..].len() as u16
    }

    pub fn payload(&self) -> Vec<u8> {
        self.raw_packet[self.hdr_len() as usize..].to_vec()
    }

    pub fn payload_range(&self, offset: usize, len: usize) -> Vec<u8> {
        self.raw_packet[offset..offset + len].to_vec()
    }

    pub fn dport(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[2..4])
    }

    pub fn sport(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[0..2])
    }

    //----------------------------------------------------
    //--- TCP Options
    //----------------------------------------------------
    fn decode_options(&mut self) {
        if self.hdr_len() > 5 {
            let start_pos = 20;
            let end_pos = self.hdr_len() as usize * 4;
            let options = self.raw_packet[start_pos..end_pos].to_vec();
            let mut ptr: usize = 0;

            while ptr < options.len() {
                match options[ptr] as u16 {
                    OPTION_NOP | OPTION_EOL => {
                        ptr += 1;
                    }
                    OPTION_MSS => {
                        ptr += 1;
                        ptr += 1;
                        self.options.mss = BigEndian::read_u16(&options[ptr..ptr + 2]);
                        ptr += 2;
                    }
                    OPTION_WINSCALE => {
                        ptr += 1;
                        ptr += 1;
                        self.options.winscale = options[ptr];
                        self.options.win_multiplier = u16::pow(2, options[ptr] as u32);
                        ptr += 1;
                    }
                    OPTION_SACK => {
                        ptr += 1;
                        self.options.sack = true;
                        ptr += 1;
                    }
                    OPTION_SACK_OPT => {
                        ptr += 1;
                        let size = options[ptr];
                        ptr += 1;
                        let count: u8 = (size - 2) / 8;
                        let mut index = 0;

                        while index < count {
                            let sack_opt = SackOpt {
                                left: BigEndian::read_u32(&options[ptr..ptr + 4]),
                                right: BigEndian::read_u32(&options[ptr + 4..ptr + 8]),
                            };
                            self.options.sack_list.push(sack_opt);
                            ptr += 8;
                            index += 1;
                        }
                    }
                    OPTION_TIMESTAMP => {
                        ptr += 1;
                        ptr += 1;
                        self.options.timestamp = Timestamp {
                            tsval: BigEndian::read_u32(&options[ptr..ptr + 4]),
                            tsecr: BigEndian::read_u32(&options[ptr + 4..ptr + 8]),
                        };
                        ptr += 8;
                    }
                    _ => {
                        println!(
                            "Options not found: {:x?}:{:x?}",
                            options[ptr..].to_vec(),
                            options
                        );
                        break;
                    }
                }
            }

            // for (k, v) in self.option_list.iter() {
            //     println!("Options: {:x}:{:x}", k, v);
            // }
            // println!("--------------------------------");
            // for s in &self.sack_list {
            //     println!("Sack: {:?}", s);
            // }
        }
    }

    pub fn is_https(&self) -> bool {
        self.sport() == 443 || self.dport() == 443
    }

    pub fn is_http(&self) -> bool {
        self.sport() == 80 || self.dport() == 80
    }

    pub fn is_ssh(&self) -> bool {
        self.sport() == 22 || self.dport() == 22
    }

    pub fn is_telnet(&self) -> bool {
        self.sport() == 23 || self.dport() == 23
    }

    pub fn is_rdp(&self) -> bool {
        self.sport() == 3389 || self.dport() == 3389
    }

    pub fn is_smtp(&self) -> bool {
        self.sport() == 25 || self.dport() == 25
    }

    pub fn is_smb(&self) -> bool {
        self.sport() == 445 || self.dport() == 445 || self.sport() == 139 || self.dport() == 139
    }
}

impl<'a> Layer for Tcp<'a> {
    fn get_field(&self, field: String) -> Option<Field> {
        match field.as_str() {
            "tcp.proto_name" => Some(Field::set_field(
                FieldType::String(String::from("TCP Level 4")),
                &field,
            )),
            "tcp.sport" => Some(Field::set_field(FieldType::Int16(self.sport()), &field)),
            "tcp.dport" => Some(Field::set_field(FieldType::Int16(self.dport()), &field)),
            "tcp.ackno" => Some(Field::set_field(FieldType::Int32(self.ack_no()), &field)),
            "tcp.seqno" => Some(Field::set_field(FieldType::Int32(self.seq_no()), &field)),
            "tcp.flags_ack" => Some(Field::set_field(FieldType::Bool(self.flag_ack()), &field)),
            "tcp.flags_push" => Some(Field::set_field(FieldType::Bool(self.flag_push()), &field)),

            "tcp.flags_syn" => Some(Field::set_field(FieldType::Bool(self.flag_syn()), &field)),
            "tcp.flags_reset" => Some(Field::set_field(FieldType::Bool(self.flag_rst()), &field)),
            "tcp.flags_fin" => Some(Field::set_field(FieldType::Bool(self.flag_fin()), &field)),
            "tcp.flags_urgent" => Some(Field::set_field(FieldType::Bool(self.flag_urg()), &field)),
            "tcp.flags_winsize" => {
                Some(Field::set_field(FieldType::Int16(self.win_size()), &field))
            }
            "tcp.hdr_len" => Some(Field::set_field(FieldType::Int8(self.hdr_len()), &field)),
            "tcp.payload_len" => Some(Field::set_field(
                FieldType::Int16(self.payload_len()),
                &field,
            )),

            "tcp.options_wscale" => Some(Field::set_field(
                FieldType::Int8(self.options.winscale),
                &field,
            )),

            "tcp.options_wscale_mult" => Some(Field::set_field(
                FieldType::Int16(self.options.win_multiplier),
                &field,
            )),

            "tcp.options_sack" => {
                Some(Field::set_field(FieldType::Bool(self.options.sack), &field))
            }

            "tcp.options_sack_count" => Some(Field::set_field(
                FieldType::Int16(self.options.sack_list.len() as u16),
                &field,
            )),

            "tcp.options_scale_le" => Some(Field::set_field(
                FieldType::Int32(self.options.sack_list[0].left),
                &field,
            )),

            "tcp.options_scale_re" => Some(Field::set_field(
                FieldType::Int32(self.options.sack_list[0].right),
                &field,
            )),

            "tcp.options_mss" => Some(Field::set_field(FieldType::Int16(self.options.mss), &field)),

            "tcp.options_timestamp" => Some(Field::set_field(
                FieldType::Int32(self.options.timestamp.tsval),
                &field,
            )),

            "tcp.options_timestamp_tsecr" => Some(Field::set_field(
                FieldType::Int32(self.options.timestamp.tsecr),
                &field,
            )),

            _ => None,
        }
    }

    fn get_field_bytes(&self, _field_name: String) -> Option<Vec<u8>> {
        None
    }

    fn get_name(&self) -> String {
        "tcp".to_string()
    }
}

impl<'a> PacketDisplay for Tcp<'a> {
    fn summary(&self) -> String {
        format!(
            "TCP -> Src port: {}, Dst port: {}, Seq: {}, MSS: {}",
            self.sport(),
            self.dport(),
            self.seq_no(),
            self.options.mss
        )
    }

    fn show_detail(&self) -> String {
        "TCP Detail".to_string()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn tcp_option_mss() {
        let packet: Vec<u8> = vec![
            0x01, 0xbb, 0xf9, 0x8b, 0x17, 0x59, 0x6d, 0xfd, 0xad, 0x4e, 0xe1, 0xfb, 0x80, 0x12,
            0xfa, 0xf0, 0x2b, 0x95, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02,
            0x01, 0x03, 0x03, 0x07,
        ];

        let pkt = Tcp::new(&packet);

        assert_eq!(pkt.options.mss, 1460);
    }

    #[test]
    fn tcp_option_wscale() {
        let packet: Vec<u8> = vec![
            0x01, 0xbb, 0xf9, 0x8b, 0x17, 0x59, 0x6d, 0xfd, 0xad, 0x4e, 0xe1, 0xfb, 0x80, 0x12,
            0xfa, 0xf0, 0x2b, 0x95, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02,
            0x01, 0x03, 0x03, 0x07,
        ];

        let pkt = Tcp::new(&packet);

        assert_eq!(pkt.options.winscale, 7);
    }

    #[test]
    fn tcp_option_wscale_multiplier() {
        let packet: Vec<u8> = vec![
            0x01, 0xbb, 0xf9, 0x8b, 0x17, 0x59, 0x6d, 0xfd, 0xad, 0x4e, 0xe1, 0xfb, 0x80, 0x12,
            0xfa, 0xf0, 0x2b, 0x95, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02,
            0x01, 0x03, 0x03, 0x07,
        ];

        let pkt = Tcp::new(&packet);

        assert_eq!(pkt.options.win_multiplier, 128);
    }

    #[test]
    fn tcp_option_timestamp() {
        let packet: Vec<u8> = vec![
            0xd2, 0xc5, 0x00, 0x16, 0x15, 0xae, 0xc5, 0x2d, 0xb9, 0xff, 0x9b, 0x26, 0x80, 0x10,
            0x07, 0xfe, 0x83, 0x11, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x73, 0x86, 0xe7, 0x26,
            0xe6, 0x3c, 0xdd, 0xfc,
        ];

        let pkt = Tcp::new(&packet);

        assert_eq!(pkt.options.timestamp.tsval, 0x7386e726);
    }

    #[test]
    fn tcp_option_timestamp_echo() {
        let packet: Vec<u8> = vec![
            0xd2, 0xc5, 0x00, 0x16, 0x15, 0xae, 0xc5, 0x2d, 0xb9, 0xff, 0x9b, 0x26, 0x80, 0x10,
            0x07, 0xfe, 0x83, 0x11, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x73, 0x86, 0xe7, 0x26,
            0xe6, 0x3c, 0xdd, 0xfc,
        ];

        let pkt = Tcp::new(&packet);

        assert_eq!(pkt.options.timestamp.tsecr, 0xe63cddfc);
    }

    #[test]
    fn tcp_frame_hdr_len() {
        let packet: Vec<u8> = vec![
            0x01, 0xbb, 0xf9, 0x8b, 0x17, 0x59, 0x6d, 0xfe, 0xad, 0x4e, 0xe4, 0x65, 0x50, 0x18,
            0x01, 0xf5, 0x67, 0xa3,
        ];

        let pkt = Tcp::new(&packet);

        assert_eq!(pkt.hdr_len(), 5);
    }

    #[test]
    fn tcp_frame_win_size() {
        let packet: Vec<u8> = vec![
            0x01, 0xbb, 0xf9, 0x8b, 0x17, 0x59, 0x6d, 0xfe, 0xad, 0x4e, 0xe4, 0x65, 0x50, 0x18,
            0x01, 0xf5, 0x67, 0xa3, 0x00, 0x00,
        ];

        let pkt = Tcp::new(&packet);

        assert_eq!(pkt.win_size(), 0x01f5);
    }

    #[test]
    fn tcp_frame_payload_len() {
        let packet: Vec<u8> = vec![
            0x01, 0xbb, 0xf9, 0x8b, 0x17, 0x59, 0x6d, 0xfe, 0xad, 0x4e, 0xe4, 0x65, 0x50, 0x18,
            0x01, 0xf5, 0x67, 0xa3, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0x80, 0x02, 0x00, 0x00,
            0x7c, 0x03, 0x03, 0xe8, 0x5f, 0xd2, 0x89, 0xa8, 0x0c, 0x9a, 0xf6, 0xed, 0xbc, 0x59,
            0x01, 0xe1, 0x39, 0xe4, 0x11, 0x29, 0x6f, 0x39, 0x38, 0xbf, 0x05, 0x6b, 0x86, 0x56,
            0xdc, 0x00, 0x46, 0x45, 0x04, 0xf2, 0xa1, 0x20, 0x82, 0xd6, 0x82, 0xca, 0x55, 0x96,
            0x13, 0x6a, 0x7b, 0x0d, 0x51, 0x2f, 0x64, 0xbf, 0x92, 0x18, 0x86, 0x40, 0x4e, 0x82,
            0xf9, 0x72, 0xa6, 0x50, 0xad, 0xfa, 0x47, 0xb7, 0xa3, 0x82, 0xad, 0x0b, 0x13, 0x02,
            0x00, 0x00, 0x34, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00,
            0x1d, 0x00, 0x20, 0x1e, 0x38, 0x49, 0xb6, 0x3f, 0xe5, 0x9f, 0xfa, 0xb2, 0x5e, 0x9d,
            0x50, 0xe6, 0x35, 0xc9, 0x30, 0xd0, 0xe4, 0x99, 0x53, 0x42, 0x54, 0x48, 0x0e, 0xdb,
            0xe2, 0x4b, 0x8f, 0x1b, 0x66, 0x91, 0x3d, 0x00, 0x29, 0x00, 0x02, 0x00, 0x00, 0x14,
            0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03, 0x00, 0x26, 0x4e, 0x8b, 0x06, 0x61,
            0x0e, 0x67, 0x67, 0xd5, 0x59, 0xf4, 0x3c, 0xc9, 0xf8, 0x21, 0xce, 0xb3, 0x30, 0xae,
            0x2f, 0xe8, 0x1a, 0xd9, 0xa1, 0xf1, 0xe1, 0xa5, 0xf3, 0x1d, 0xc0, 0x19, 0x68, 0xc5,
            0x6c, 0xa5, 0xaf, 0x8c, 0x46, 0xb8, 0x17, 0x03, 0x03, 0x00, 0x45, 0xe3, 0x04, 0xf4,
            0x3d, 0x28, 0xa6, 0x31, 0xbe, 0x6b, 0xf7, 0x5c, 0x3a, 0x21, 0xb8, 0xd9, 0xb1, 0xdb,
            0x32, 0x3a, 0xfe, 0x41, 0x68, 0x9e, 0xcc, 0x01, 0x9d, 0x15, 0x4d, 0x0d, 0xdc, 0x51,
            0xb0, 0xa8, 0xce, 0x81, 0x88, 0x2e, 0x5e, 0x49, 0xd5, 0x5e, 0xe8, 0x96, 0x5e, 0xa9,
            0x13, 0xb6, 0x7b, 0x2f, 0x2c, 0xbe, 0x35, 0x46, 0x73, 0x2d, 0xf6, 0x39, 0x6d, 0x09,
            0x20, 0x3e, 0xb7, 0x05, 0x15, 0x2f, 0xfa, 0x28, 0x89, 0xcc,
        ];

        let pkt = Tcp::new(&packet);

        assert_eq!(pkt.payload_len(), 256);
    }

    #[test]
    fn tcp_frame() {
        let packet: Vec<u8> = vec![
            0xc8, 0xcf, 0x01, 0xbd, 0x1e, 0x54, 0x73, 0xc3, 0xe4, 0x56, 0x89, 0x7c, 0x50, 0x18,
            0x20, 0x35, 0x7c, 0xbf, 0x00, 0x00,
        ];

        let pkt = Tcp::new(&packet);

        assert_eq!(pkt.sport(), 0xc8cf);
        assert_eq!(pkt.dport(), 0x01bd);
    }

    #[test]
    fn tcp_frame_seq() {
        let packet: Vec<u8> = vec![
            0xc8, 0xcf, 0x01, 0xbd, 0x1e, 0x54, 0x73, 0xc3, 0xe4, 0x56, 0x89, 0x7c, 0x50, 0x18,
            0x20, 0x35, 0x7c, 0xbf, 0x00, 0x00,
        ];

        let pkt = Tcp::new(&packet);

        assert_eq!(pkt.seq_no(), 0x1e5473c3);
    }

    #[test]
    fn tcp_frame_ack_seq() {
        let packet: Vec<u8> = vec![
            0xc8, 0xcf, 0x01, 0xbd, 0x1e, 0x54, 0x73, 0xc3, 0xe4, 0x56, 0x89, 0x7c, 0x50, 0x18,
            0x20, 0x35, 0x7c, 0xbf, 0x00, 0x00,
        ];

        let pkt = Tcp::new(&packet);

        assert_eq!(pkt.ack_no(), 0xe456897c);
    }

    #[test]
    fn tcp_frame_ack_push_flags() {
        let packet: Vec<u8> = vec![
            0xc8, 0xcf, 0x01, 0xbd, 0x1e, 0x54, 0x73, 0xc3, 0xe4, 0x56, 0x89, 0x7c, 0x50, 0x18,
            0x20, 0x35, 0x7c, 0xbf, 0x00, 0x00,
        ];

        let pkt = Tcp::new(&packet);

        assert!(pkt.flag_ack());
        assert!(pkt.flag_push());
        assert!(!pkt.flag_syn());
        assert!(!pkt.flag_rst());
        assert!(!pkt.flag_fin());
    }

    #[test]
    fn tcp_frame_syn_flag() {
        let packet: Vec<u8> = vec![
            0xd1, 0x61, 0x0c, 0x38, 0x0c, 0xdd, 0x67, 0xf5, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02,
            0xfa, 0xf0, 0xa0, 0x05, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x08,
            0x01, 0x01, 0x04, 0x02,
        ];

        let pkt = Tcp::new(&packet);

        assert!(pkt.flag_syn());
        assert!(!pkt.flag_ack());
        assert!(!pkt.flag_push());
        assert!(!pkt.flag_rst());
        assert!(!pkt.flag_fin());
    }

    #[test]
    fn tcp_frame_reset_flag() {
        let packet: Vec<u8> = vec![
            0xf4, 0xee, 0x01, 0xbb, 0x53, 0x86, 0x2d, 0x5c, 0x25, 0xc4, 0x61, 0x37, 0x50, 0x14,
            0x00, 0x00, 0x6f, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let pkt = Tcp::new(&packet);

        assert!(pkt.flag_rst());
        assert!(!pkt.flag_syn());
        assert!(pkt.flag_ack(), "Ack flag");
        assert!(!pkt.flag_push());
        assert!(!pkt.flag_fin());
    }
}
