pub fn string_mac_to_int(ip_str: String) -> u64 {
    let mut result: u64 = 0;
    let mut int_field: u64;

    let fields: Vec<&str> = ip_str.split(":").collect();
    if fields.len() == 6 {
        int_field = u64::from_str_radix(fields[0], 16).unwrap();
        result += int_field << 40;

        int_field = u64::from_str_radix(fields[1], 16).unwrap();
        result += int_field << 32;

        int_field = u64::from_str_radix(fields[2], 16).unwrap();
        result += int_field << 24;

        int_field = u64::from_str_radix(fields[3], 16).unwrap();
        result += int_field << 16;

        int_field = u64::from_str_radix(fields[4], 16).unwrap();
        result += int_field << 8;

        int_field = u64::from_str_radix(fields[5], 16).unwrap();
        result += int_field;
    }

    result
}

pub fn mac_to_string(mac: &u64) -> String {
    let result: String;

    result = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        (mac >> 40) as u8,
        (mac >> 32) as u8,
        (mac >> 24) as u8,
        (mac >> 16) as u8,
        (mac >> 8) as u8,
        (mac & 0xff) as u8
    );

    result
}
