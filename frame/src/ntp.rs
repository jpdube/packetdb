use crate::layer::Layer;
use byteorder::{BigEndian, ByteOrder};
use field::pfield::{Field, FieldType};

#[derive(Debug, Clone)]
pub struct Ntp<'a> {
    raw_data: &'a [u8],
}

impl<'a> Ntp<'a> {
    pub fn new(raw_data: &'a [u8]) -> Self {
        Self { raw_data }
    }

    pub fn leap_indicator(&self) -> u8 {
        (self.raw_data[0] & 0b11000000) >> 6
    }

    pub fn version_no(&self) -> u8 {
        (self.raw_data[0] & 0b00111000) >> 3
    }

    pub fn mode(&self) -> u8 {
        self.raw_data[0] & 0b00000111
    }

    pub fn stratum(&self) -> u8 {
        self.raw_data[1]
    }

    pub fn poll(&self) -> u8 {
        self.raw_data[2]
    }

    pub fn precision(&self) -> u8 {
        self.raw_data[3]
    }

    pub fn root_delay(&self) -> u32 {
        BigEndian::read_u32(&self.raw_data[4..8])
    }

    pub fn root_dispersion(&self) -> u32 {
        BigEndian::read_u32(&self.raw_data[8..12])
    }

    pub fn ref_id(&self) -> u32 {
        BigEndian::read_u32(&self.raw_data[12..16])
    }

    pub fn ref_timestamp(&self) -> u64 {
        BigEndian::read_u64(&self.raw_data[16..24])
    }

    pub fn origin_timestamp(&self) -> u64 {
        BigEndian::read_u64(&self.raw_data[24..32])
    }

    pub fn recv_timestamp(&self) -> u64 {
        BigEndian::read_u64(&self.raw_data[32..40])
    }

    pub fn xmit_timestamp(&self) -> u64 {
        BigEndian::read_u64(&self.raw_data[40..48])
    }

    pub fn optional_ext(&self) -> u32 {
        BigEndian::read_u32(&self.raw_data[48..52])
    }

    pub fn key_id(&self) -> u32 {
        BigEndian::read_u32(&self.raw_data[52..56])
    }

    pub fn msg_digest(&self) -> Vec<u8> {
        self.raw_data[52..].to_vec()
    }

    fn mode_str(&self) -> String {
        let mode_str: &str;

        match self.mode() {
            3 => mode_str = "Client",
            4 => mode_str = "Server",
            _ => mode_str = "Undefined",
        }

        mode_str.to_string()
    }
}

impl<'a> Layer for Ntp<'a> {
    fn get_name(&self) -> String {
        "ntp".to_string()
    }

    fn get_field(&self, field: String) -> Option<Field> {
        match field.as_str() {
            "ntp.leap_indicator" => Some(Field::set_field(
                FieldType::Int8(self.leap_indicator()),
                field,
            )),

            "ntp.version" => Some(Field::set_field(FieldType::Int8(self.version_no()), field)),
            "ntp.mode" => Some(Field::set_field(FieldType::Int8(self.mode()), field)),
            "mtp.mode_label" => Some(Field::set_field(FieldType::String(self.mode_str()), field)),

            "ntp.stratum" => Some(Field::set_field(FieldType::Int8(self.stratum()), field)),
            "ntp.poll" => Some(Field::set_field(FieldType::Int8(self.poll()), field)),
            "ntp.precision" => Some(Field::set_field(FieldType::Int8(self.precision()), field)),
            "ntp.root_delay" => Some(Field::set_field(FieldType::Int32(self.root_delay()), field)),
            "ntp.root_dispersion" => Some(Field::set_field(
                FieldType::Int32(self.root_dispersion()),
                field,
            )),
            "ntp.ref_id" => Some(Field::set_field(FieldType::Int32(self.ref_id()), field)),
            "ntp.ref_timestamp" => Some(Field::set_field(
                FieldType::Int64(self.ref_timestamp()),
                field,
            )),
            "ntp.origin_timestamp" => Some(Field::set_field(
                FieldType::Int64(self.origin_timestamp()),
                field,
            )),
            "ntp.recv_timestamp" => Some(Field::set_field(
                FieldType::Int64(self.recv_timestamp()),
                field,
            )),
            "ntp.xmit_timestamp" => Some(Field::set_field(
                FieldType::Int64(self.xmit_timestamp()),
                field,
            )),
            "ntp.opt_extension" => Some(Field::set_field(
                FieldType::Int32(self.optional_ext()),
                field,
            )),
            "ntp.key_id" => Some(Field::set_field(
                FieldType::ByteArray(self.msg_digest()),
                field,
            )),
            _ => None,
        }
    }

    fn get_field_bytes(&self, _field: String) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_packet() -> Vec<u8> {
        let packet: Vec<u8> = vec![
            0xd9, 0x0, 0x11, 0xe9, 0x0, 0x0, 0x10, 0xb4, 0x0, 0x4, 0xdf, 0xa0, 0x0, 0x0, 0x0, 0x0,
            0xe5, 0xde, 0xdd, 0xd2, 0x83, 0xb, 0x21, 0x9c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xe5, 0xde, 0xdd, 0xda, 0x5e, 0xf2, 0xa2, 0x49,
            0x63, 0x68, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0,
        ];

        packet
    }
    #[test]
    fn test_leap_indicator() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(ntp.leap_indicator(), 3, "Leap indicator");
    }

    #[test]
    fn test_stratum() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(ntp.stratum(), 0, "Stratum");
    }

    #[test]
    fn test_poll() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(ntp.poll(), 17, "Poll");
    }

    #[test]
    fn test_precision() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(ntp.precision(), 0xe9, "Precision");
    }

    #[test]
    fn test_root_delay() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(ntp.root_delay(), 0x10b4, "Root delay");
    }

    #[test]
    fn test_root_dispersion() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(ntp.root_dispersion(), 0x0004dfa0, "Root dispersion");
    }

    #[test]
    fn test_ref_id() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(ntp.ref_id(), 0x0, "Reference ID");
    }

    #[test]
    fn test_ref_timestamp() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(
            ntp.ref_timestamp(),
            0xe5deddd2830b219c,
            "Reference timestamp"
        );
    }

    #[test]
    fn test_origin_timestamp() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(ntp.origin_timestamp(), 0x0, "Origin timestamp");
    }

    #[test]
    fn test_recv_timestamp() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(ntp.recv_timestamp(), 0x0, "Received timestamp");
    }

    #[test]
    fn test_xmit_timestamp() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(
            ntp.xmit_timestamp(),
            0xe5deddda5ef2a249,
            "Transmit timestamp"
        );
    }

    #[test]
    fn test_key_id() {
        let packet = get_packet();

        let ntp = Ntp::new(&packet);
        assert_eq!(ntp.optional_ext(), 0x63680000, "Key ID");
    }
}
