pub fn format_hex(bytes: Vec<u8>) -> String {
    let mut count: usize = 0;
    let mut byte_count: usize = 0;
    let mut result: String = String::new();

    for i in bytes.clone() {
        if count == 0 {
            result.push_str(&format!("{:04x}: ", byte_count));
        }

        result.push_str(&format!("{:02x} ", i));
        count += 1;
        byte_count += 1;

        if count == 8 {
            result.push(' ');
        }

        if count == 16 {
            result.push_str(&get_char(bytes[byte_count - 16..byte_count].to_vec()));
            result.push('\n');
            count = 0;
        }
    }

    let spacing: usize = (16 - count) * 3;

    // if count <= 8 {
    //     spacing += 1;
    // }

    result.push_str(&" ".repeat(spacing));
    result.push_str(&get_char(bytes[byte_count - count..byte_count].to_vec()));
    result
}

pub fn print_hex(bytes: Vec<u8>) {
    println!("{}", format_hex(bytes));
}

fn get_char(bytes: Vec<u8>) -> String {
    let mut result: String = String::new();

    for i in bytes {
        if (0x21..=0x7e).contains(&i) {
            // if i >= 0x21 && i <= 0x7e {
            result.push(i as char);
        } else {
            result.push('\u{00b7}');
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_8_bytes() {
        let bytes: Vec<u8> = vec![0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48];
        print_hex(bytes)
    }

    #[test]
    fn test_9_bytes() {
        let bytes: Vec<u8> = vec![0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49];
        print_hex(bytes)
    }

    #[test]
    fn test_16_bytes() {
        let bytes: Vec<u8> = vec![
            0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x11, 0x22,
            0x33, 0x44,
        ];
        print_hex(bytes)
    }

    #[test]
    fn test_32_bytes() {
        let bytes: Vec<u8> = vec![
            0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x11, 0x22,
            0x33, 0x44, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6,
            0x11, 0x22, 0x33, 0x44,
        ];
        print_hex(bytes)
    }

    #[test]
    fn test_32_chars() {
        let mut bytes: Vec<u8> = Vec::new();
        let mut j: u8 = 0;

        for _i in 0..255 {
            bytes.push(j);
            j += 1;
        }

        print_hex(bytes)
    }
}
