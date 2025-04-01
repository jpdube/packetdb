use crate::fields;
use crate::ipv4_address::IPv4;
use crate::layer::Layer;
use crate::pfield::{Field, FieldType};
use crate::print_hex::print_hex;
use ::chrono::prelude::*;
use byteorder::{BigEndian, ByteOrder};
use std::fmt;
use std::str;
/*
All RRs have the same top level format shown below:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


where:

NAME            an owner name, i.e., the name of the node to which this
                resource record pertains.

TYPE            two octets containing one of the RR TYPE codes.

CLASS           two octets containing one of the RR CLASS codes.

TTL             a 32 bit signed integer that specifies the time interval
                that the resource record may be cached before the source
                of the information should again be consulted.  Zero
                values are interpreted to mean that the RR can only be
                used for the transaction in progress, and should not be
                cached.  For example, SOA records are always distributed
                with a zero TTL to prohibit caching.  Zero values can
                also be used for extremely volatile data.

RDLENGTH        an unsigned 16 bit integer that specifies the length in
                octets of the RDATA field.



Mockapetris                                                    [Page 11]

RFC 1035        Domain Implementation and Specification    November 1987


RDATA           a variable length string of octets that describes the
                resource.  The format of this information varies
                according to the TYPE and CLASS of the resource record.

3.2.2. TYPE values

TYPE fields are used in resource records.  Note that these types are a
subset of QTYPEs.

TYPE            value and meaning

A               1 a host address

NS              2 an authoritative name server

MD              3 a mail destination (Obsolete - use MX)

MF              4 a mail forwarder (Obsolete - use MX)

CNAME           5 the canonical name for an alias

SOA             6 marks the start of a zone of authority

MB              7 a mailbox domain name (EXPERIMENTAL)

MG              8 a mail group member (EXPERIMENTAL)

MR              9 a mail rename domain name (EXPERIMENTAL)

NULL            10 a null RR (EXPERIMENTAL)

WKS             11 a well known service description

PTR             12 a domain name pointer

HINFO           13 host information

MINFO           14 mailbox or mail list information

MX              15 mail exchange

TXT             16 text strings

3.2.3. QTYPE values

QTYPE fields appear in the question part of a query.  QTYPES are a
superset of TYPEs, hence all TYPEs are valid QTYPEs.  In addition, the
following QTYPEs are defined:



Mockapetris                                                    [Page 12]

RFC 1035        Domain Implementation and Specification    November 1987


AXFR            252 A request for a transfer of an entire zone

MAILB           253 A request for mailbox-related records (MB, MG or MR)

MAILA           254 A request for mail agent RRs (Obsolete - see MX)

                255 A request for all records
*/

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_SRV: u16 = 33;
pub const DNS_TYPE_RRSIG: u16 = 0x2e;

pub const DNS_CLASS_IN: u16 = 1;

fn rtype_to_str(rtype: u16) -> String {
    match rtype {
        DNS_TYPE_A => String::from("A (1)"),
        DNS_TYPE_CNAME => String::from("CNAME (5)"),
        DNS_TYPE_MX => String::from("MX (15)"),
        DNS_TYPE_PTR => String::from("PTR (12)"),
        DNS_TYPE_TXT => String::from("TXT (16)"),
        DNS_TYPE_SOA => String::from("SOA (6)"),
        DNS_TYPE_SRV => String::from("SRV (33)"),
        _ => String::from("NONE"),
    }
}

fn class_to_str(rtype: u16) -> String {
    match rtype {
        DNS_CLASS_IN => String::from("IN"),
        _ => String::from("NONE"),
    }
}

#[derive(Debug, Default, Clone)]
pub struct Srv {
    service: String,
    protocol: String,
    // rtype: u16,
    // class: u16,
    // ttl: u32,
    // rdlength: u16,
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
}

impl fmt::Display for Srv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Service: {}, Protocol: {}, Priority: {},  Weight: {}, Port: {}, Target: {}",
            self.service, self.protocol, self.priority, self.weight, self.port, self.target,
        )
    }
}

#[derive(Debug, Default, Clone)]
struct RRsig {
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    orig_ttl: u32,
    sig_expiration: u32,
    sig_inception: u32,
    key_tag: u16,
    signer_name: String,
    signature: Vec<u8>,
}

impl fmt::Display for RRsig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Type covered: {}, Algorithm: {:0x}, Labels: {}, Origin TTL: {},  Signature expiration: {} - {:0x}, Signature inception: {} - {:0x}, Key tag: {:0x}, Signature name: {}, Signature: {:x?}",
            rtype_to_str(self.type_covered),
            self.algorithm,
            self.labels,
            self.orig_ttl,
            timestamp_str(&self.sig_expiration),
            self.sig_expiration,
            timestamp_str(&self.sig_inception),
            self.sig_inception,
            self.key_tag,
            self.signer_name,
            self.signature
        )
    }
}

fn timestamp_str(ts: &u32) -> String {
    let naive = Utc.timestamp_opt(*ts as i64, 0).unwrap();
    let timestamp = naive.format("%Y-%m-%d %H:%M:%S");
    format!("{}", timestamp)
}

#[derive(Debug, Default, Clone)]
pub struct Answer {
    name: String,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdlength: usize,
    cname: String,
    address: u32,
    txt: String,
    asize: usize,
    srv: Srv,
    rrsig: Option<RRsig>,
}

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Label: {}, Type: {}, Class: {}, TTL: {},  Data length: {}, CNAME: {}, TXT: {}, Address: {}, Nbr bytes: {}, Srv: {}",
            self.name,
            rtype_to_str(self.rtype),
            class_to_str(self.class),
            self.ttl,
            self.rdlength,
            self.cname,
            self.txt,
            IPv4::new(self.address, 32).to_string(),
            self.asize,
            self.srv,
        )
    }
}

impl<'a> Answer {
    pub fn decode(&mut self, raw_data: &'a [u8], offset: usize, id: u16) {
        let mut index: usize = offset;
        let start_pos;

        // println!("Answer decode offset: {:0x}", offset);
        self.name = get_name(raw_data, offset, id);

        if raw_data[offset] == 0xc0 {
            index += 2;
        } else {
            index += self.name.len() + 2;
        }

        self.rtype = BigEndian::read_u16(&raw_data[index..index + 2]);
        index += 2;
        self.class = BigEndian::read_u16(&raw_data[index..index + 2]);
        index += 2;
        self.ttl = BigEndian::read_u32(&raw_data[index..index + 4]);
        index += 4;
        self.rdlength = BigEndian::read_u16(&raw_data[index..index + 2]) as usize;
        index += 2;

        match self.rtype {
            DNS_TYPE_CNAME => {
                self.cname = get_name(&raw_data, index, id);
                self.asize = index + self.rdlength;
            }
            DNS_TYPE_A => {
                self.address = BigEndian::read_u32(&raw_data[index..index + 4]);
                self.asize = index + 4;
            }
            DNS_TYPE_TXT => {
                self.txt =
                    String::from(str::from_utf8(&raw_data[index..index + self.rdlength]).unwrap());
                self.asize = index + self.txt.len();
            }

            DNS_TYPE_SRV => {
                let mut srv_rec = Srv::default();

                let fields = self.name.split(".").collect::<Vec<&str>>();

                if fields.len() > 2 {
                    srv_rec.service = fields[0].to_string();
                    srv_rec.protocol = fields[1].to_string();
                } else {
                    srv_rec.service = "undefined".to_string();
                    srv_rec.protocol = "undefined".to_string();
                }

                srv_rec.priority = BigEndian::read_u16(&raw_data[index..index + 2]);
                index += 2;

                srv_rec.weight = BigEndian::read_u16(&raw_data[index..index + 2]);
                index += 2;

                srv_rec.port = BigEndian::read_u16(&raw_data[index..index + 2]);
                index += 2;

                srv_rec.target = get_name(&raw_data, index, id);

                self.srv = srv_rec;

                // println!("SRV RECORD: {}", self);
            }
            DNS_TYPE_RRSIG => {
                let mut rrsig = RRsig::default();

                start_pos = index;
                self.asize = index + self.rdlength;

                rrsig.type_covered = BigEndian::read_u16(&raw_data[index..index + 2]);
                index += 2;

                rrsig.algorithm = raw_data[index];
                index += 1;

                rrsig.labels = raw_data[index];
                index += 1;

                rrsig.orig_ttl = BigEndian::read_u32(&raw_data[index..index + 4]);
                index += 4;

                rrsig.sig_expiration = BigEndian::read_u32(&raw_data[index..index + 4]);
                index += 4;

                rrsig.sig_inception = BigEndian::read_u32(&raw_data[index..index + 4]);
                index += 4;

                rrsig.key_tag = BigEndian::read_u16(&raw_data[index..index + 2]);
                index += 2;

                rrsig.signer_name = get_name(&raw_data, index, id);
                if raw_data[index] == 0xc0 {
                    index += 2;
                } else {
                    index += rrsig.signer_name.len() + 2;
                }
                // index = index + rrsig.signer_name.len() + 2;

                let sig_len = index - start_pos;
                // println!(
                //     "SIG len: {}, index: {}, length: {}",
                //     sig_len, index, self.rdlength
                // );
                rrsig.signature = raw_data[index..index + (self.rdlength - sig_len)].to_vec();

                self.rrsig = Some(rrsig);
                // index += self.rdlength - sig_len;
                println!("RRsig answer len: {}", self.asize);
            }

            _ => {}
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Query {
    name: String,
    rtype: u16,
    class: u16,
    qsize: usize,
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Label: {}, Type: {}, Class: {} Size: {}",
            self.name,
            rtype_to_str(self.rtype),
            class_to_str(self.class),
            self.qsize,
        )
    }
}

impl<'a> Query {
    pub fn decode(&mut self, raw_data: &'a [u8], offset: usize, id: u16) {
        self.name = get_name(raw_data, offset, id);

        let mut index = offset + self.name.len() + 2;
        // println!(
        //     "Offset: {:x}, Index: {:x}, Name len: {:x}",
        //     offset,
        //     index,
        //     self.name.len()
        // );
        self.rtype = BigEndian::read_u16(&raw_data[index..index + 2]);
        index += 2;
        self.class = BigEndian::read_u16(&raw_data[index..index + 2]);

        self.qsize = self.name.len() + 2 + 2 + 2;

        // println!("{}", self);
    }
}

#[derive(Debug, Default, Clone)]
pub struct Dns<'a> {
    raw_packet: &'a [u8],
    offset: usize,
    query_list: Vec<Query>,
    answer_list: Vec<Answer>,
}

impl<'a> Dns<'a> {
    pub fn new(packet: &'a [u8]) -> Self {
        let mut my_self = Self {
            raw_packet: packet,
            offset: 12,
            query_list: Vec::new(),
            answer_list: Vec::new(),
        };

        my_self.decode();

        my_self
    }

    pub fn id(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[0..2])
    }

    pub fn flags(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[2..4])
    }

    pub fn is_query(&self) -> bool {
        (self.flags() & 0x8000) == 0
    }

    pub fn is_response(&self) -> bool {
        self.is_query() == false
    }

    pub fn opcode(&self) -> u8 {
        (self.flags() & 0x78) as u8
    }

    pub fn question_count(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[4..6])
    }

    pub fn answer_count(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[6..8])
    }

    pub fn ns_count(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[8..10])
    }

    pub fn authority_count(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[10..12])
    }

    pub fn is_authoritative(&self) -> bool {
        (self.flags() & 0x0400) == 0x0400
    }

    pub fn recursion_desired(&self) -> bool {
        (self.flags() & 0x0100) == 0x0100
    }

    pub fn recursion_available(&self) -> bool {
        (self.flags() & 0x80) == 0x80
    }

    pub fn answer_authenticated(&self) -> bool {
        (self.flags() & 0x20) == 0x20
    }

    pub fn non_authenticated(&self) -> bool {
        (self.flags() & 0x10) == 0x10
    }

    pub fn reply_code(&self) -> u8 {
        (self.flags() & 0x000f) as u8
    }

    pub fn has_rrsig(&self) -> bool {
        for anw in &self.answer_list {
            if anw.rrsig.is_some() {
                return true;
            }
        }

        false
    }

    pub fn decode(&mut self) {
        self.offset = 12;
        // println!("+++> ID: {:x}", self.id());
        self.process_queries();
        self.process_answers();
    }

    fn process_queries(&mut self) {
        for _ in 0..self.question_count() {
            let mut query = Query::default();
            query.decode(self.raw_packet, self.offset, self.id());
            self.offset += query.qsize;

            self.query_list.push(query);
        }
    }

    fn process_answers(&mut self) {
        for _ in 0..self.answer_count() {
            let mut answer = Answer::default();
            answer.decode(self.raw_packet, self.offset, self.id());

            self.offset = answer.asize;
            self.answer_list.push(answer);
        }
    }
}

impl<'a> Layer for Dns<'a> {
    fn get_name(&self) -> String {
        "dns".to_string()
    }

    fn get_field(&self, field: u32) -> Option<Field> {
        match field {
            fields::DNS_ID => Some(Field::set_field(FieldType::Int16(self.id()), field)),
            fields::DNS_OPCODE => Some(Field::set_field(FieldType::Int8(self.opcode()), field)),
            fields::DNS_HAS_RRSIG => {
                Some(Field::set_field(FieldType::Bool(self.has_rrsig()), field))
            }
            fields::DNS_ANSWER_COUNT => Some(Field::set_field(
                FieldType::Int16(self.answer_count()),
                field,
            )),
            fields::DNS_QUESTION_COUNT => Some(Field::set_field(
                FieldType::Int16(self.question_count()),
                field,
            )),
            fields::DNS_ANSWERS => {
                let mut field_list: Vec<Box<FieldType>> = Vec::new();

                for answer in &self.answer_list {
                    field_list.push(Box::new(FieldType::String(answer.name.clone())));
                    // field_list.push(Box::new(FieldType::Int16(12345)));
                }

                Some(Field::set_field(FieldType::FieldArray(field_list), field))
            }
            _ => None,
        }
    }

    fn get_field_bytes(&self, _field_name: u32) -> Option<Vec<u8>> {
        None
    }
}

fn get_name(raw_packet: &[u8], start_pos: usize, id: u16) -> String {
    let mut offset = start_pos;
    let mut count: usize;
    let mut temp_name: String;
    let mut seperator = "";

    temp_name = String::new();
    loop {
        count = raw_packet[offset] as usize;
        // println!("Offset: {:0x}, Count: {:0x}", offset, count);

        if count == 0 {
            break;
        } else if count == 0xc0 {
            while count == 0xc0 {
                offset = raw_packet[offset + 1] as usize;

                count = raw_packet[offset] as usize;
            }
        }

        offset += 1;

        if (offset + count) > raw_packet.len() {
            eprintln!("==========================================================");
            eprintln!(
                "Error: ID: {:x} offset: {} count: {}, offset + count: {}, byte len: {}",
                id,
                offset,
                count,
                offset + count,
                raw_packet.len()
            );
            print_hex(raw_packet.to_vec());
            eprintln!("==========================================================");
            break;
        }

        if temp_name.len() != 0 {
            seperator = "."
        }
        // println!("Offset: {:0x}, Count: {:0x}", offset, count);
        // print_hex(raw_packet[offset..offset + count].to_vec());

        match str::from_utf8(&raw_packet[offset..offset + count]) {
            Ok(name) => {
                temp_name = format!("{}{}{}", temp_name, seperator, name);
                // println!("---> {}", temp_name);
            }
            Err(msg) => {
                eprintln!("Error reading label: {}", msg);
                print_hex(raw_packet[offset..offset + count].to_vec());
            }
        }

        offset += count;
    }

    return temp_name;
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Original packet, extractions are used below
    // -----------------------------------------------
    // let packet: Vec<u8> = vec![
    // 0x11, 0x7e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x20, 0x66, 0x38, 0x35, 0x39, 0x61, 0x35, 0x39, 0x64,
    // 0x62, 0x36, 0x62, 0x37, 0x64, 0x30, 0x38, 0x62, 0x64, 0x33, 0x38, 0x38, 0x34, 0x62, 0x36, 0x39, 0x32, 0x31, 0x65, 0x35, 0x61,
    // 0x35, 0x30, 0x64, 0x02, 0x66, 0x70, 0x07, 0x6d, 0x65, 0x61, 0x73, 0x75, 0x72, 0x65, 0x06, 0x6f, 0x66, 0x66, 0x69, 0x63, 0x65,
    // 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x0f,
    // 0x07, 0x6f, 0x75, 0x74, 0x6c, 0x6f, 0x6f, 0x6b, 0x04, 0x6c, 0x69, 0x76, 0x65, 0xc0, 0x3f, 0xc0, 0x54, 0x00, 0x05, 0x00, 0x01,
    // 0x00, 0x00, 0x00, 0xb6, 0x00, 0x17, 0x07, 0x6f, 0x75, 0x74, 0x6c, 0x6f, 0x6f, 0x6b, 0x02, 0x68, 0x61, 0x09, 0x6f, 0x66, 0x66,
    // 0x69, 0x63, 0x65, 0x33, 0x36, 0x35, 0xc0, 0x3f, 0xc0, 0x6f, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x12, 0x07,
    // 0x6f, 0x75, 0x74, 0x6c, 0x6f, 0x6f, 0x6b, 0x07, 0x6d, 0x73, 0x2d, 0x61, 0x63, 0x64, 0x63, 0xc0, 0x38, 0xc0, 0x92, 0x00, 0x05,
    // 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x0a, 0x07, 0x59, 0x51, 0x42, 0x2d, 0x65, 0x66, 0x7a, 0xc0, 0x9a, 0xc0, 0xb0, 0x00,
    // 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x34, 0x60, 0x58, 0x92, 0xc0, 0xb0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    // 0x00, 0x04, 0x00, 0x04, 0x34, 0x60, 0xe6, 0x32, 0xc0, 0xb0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x34,
    // 0x60, 0xa3, 0xf2, 0xc0, 0xb0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x34, 0x60, 0x58, 0xb2, 0x00, 0x00,
    // 0x29, 0x02, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00
    // ];

    //--- Response packet
    // let packet: Vec<u8> = vec![
    //     0x7f, 0x19, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x5f,
    //     0x6c, 0x64, 0x61, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x03, 0x70, 0x64, 0x63, 0x06,
    //     0x5f, 0x6d, 0x73, 0x64, 0x63, 0x73, 0x07, 0x6c, 0x61, 0x6c, 0x6c, 0x69, 0x65, 0x72,
    //     0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x21, 0x00, 0x01, 0xc0, 0x0c, 0x00,
    //     0x21, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x21, 0x00, 0x00, 0x00, 0x64, 0x01,
    //     0x85, 0x0b, 0x6d, 0x74, 0x6c, 0x2d, 0x73, 0x72, 0x76, 0x2d, 0x61, 0x64, 0x32, 0x07,
    //     0x6c, 0x61, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
    //     0xc0, 0x47, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0xc0, 0xa8,
    //     0x02, 0xe6,
    // ];

    #[test]
    fn dns_id() {
        let packet: Vec<u8> = vec![
            0x11, 0x7e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x20, 0x66,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.id(), 0x117e, "DNS ID");
        assert_eq!(pkt.flags(), 0x8180, "DNS Flags");
        assert_eq!(pkt.question_count(), 1, "DNS Question");
    }

    #[test]
    fn dns_flags() {
        let packet: Vec<u8> = vec![
            0x11, 0x7e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x20, 0x66,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.flags(), 0x8180, "DNS Flags");
    }

    #[test]
    fn dns_nbr_questions() {
        let packet: Vec<u8> = vec![
            0x11, 0x7e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x20, 0x66,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.question_count(), 1, "DNS Question");
    }

    #[test]
    fn dns_is_query_false() {
        let packet: Vec<u8> = vec![
            0x11, 0x7e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x20, 0x66,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.is_query(), false, "DNS is query");
    }

    #[test]
    fn dns_is_response_true() {
        let packet: Vec<u8> = vec![
            0x11, 0x7e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x20, 0x66,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.is_response(), true, "DNS is response");
    }

    #[test]
    fn dns_is_query_true() {
        let packet: Vec<u8> = vec![
            0x11, 0x7e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x20, 0x66,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.is_query(), true, "DNS is query");
    }

    #[test]
    fn dns_is_response_false() {
        let packet: Vec<u8> = vec![
            0x11, 0x7e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x20, 0x66,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.is_response(), false, "DNS is response");
    }

    #[test]
    fn dns_opcode() {
        let packet: Vec<u8> = vec![
            0x11, 0x7e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x20, 0x66,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.opcode(), 0, "DNS is query");
    }

    #[test]
    fn dns_is_authoritative_true() {
        let packet: Vec<u8> = vec![
            0x7f, 0x19, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x5f,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.is_authoritative(), true, "DNS is authoritative");
    }

    #[test]
    fn dns_recursion_desired_true() {
        let packet: Vec<u8> = vec![
            0x7f, 0x19, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x5f,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.recursion_desired(), true, "DNS recursion desired");
    }

    #[test]
    fn dns_recursion_available_true() {
        let packet: Vec<u8> = vec![
            0x7f, 0x19, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x5f,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(
            pkt.recursion_available(),
            true,
            "DNS is recursion available"
        );
    }

    #[test]
    fn dns_answer_authenticated_false() {
        let packet: Vec<u8> = vec![
            0x7f, 0x19, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x5f,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.answer_authenticated(), false, "DNS is authenticated");
    }

    #[test]
    fn dns_non_authenticated() {
        let packet: Vec<u8> = vec![
            0x7f, 0x19, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x5f,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.non_authenticated(), false, "DNS is non authenticated");
    }

    #[test]
    fn dns_reply_code() {
        let packet: Vec<u8> = vec![
            0x7f, 0x19, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x5f,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.reply_code(), 0, "DNS reply code = 0");
    }

    #[test]
    fn dns_qd_count() {
        let packet: Vec<u8> = vec![
            0x7f, 0x19, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x5f,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.question_count(), 1, "DNS question count");
    }

    #[test]
    fn dns_answer_rr() {
        let packet: Vec<u8> = vec![
            0x7f, 0x19, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x5f,
            0x6c, 0x64, 0x61, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x03, 0x70, 0x64, 0x63, 0x06,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.authority_count(), 1, "DNS answer count");
    }

    #[test]
    fn dns_authority_rr() {
        let packet: Vec<u8> = vec![
            0x7f, 0x19, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x5f,
            0x6c, 0x64, 0x61, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x03, 0x70, 0x64, 0x63, 0x06,
        ];

        let pkt = Dns::new(&packet);

        assert_eq!(pkt.answer_count(), 1, "DNS authority");
    }

    #[test]
    fn dns_process_query() {
        let packet: Vec<u8> = vec![
            0x9a, 0x04, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x76,
            0x31, 0x30, 0x06, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x04, 0x64, 0x61, 0x74, 0x61,
            0x09, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x03, 0x63, 0x6f, 0x6d,
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let mut pkt = Dns::new(&packet);
        pkt.process_queries();

        assert_eq!(pkt.query_list.len(), 1, "DNS question count should be 1");

        // pkt.offset = 12;
        assert_eq!(
            pkt.query_list[0].name, "v10.events.data.microsoft.com",
            "DNS question name"
        );
    }

    #[test]
    fn dns_process_query_3_part_domain() {
        let packet: Vec<u8> = vec![
            0xd2, 0x33, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x5f,
            0x6c, 0x64, 0x61, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x03, 0x70, 0x64, 0x63, 0x06,
            0x5f, 0x6d, 0x73, 0x64, 0x63, 0x73, 0x07, 0x6c, 0x61, 0x6c, 0x6c, 0x69, 0x65, 0x72,
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x21, 0x00, 0x01, 0xc0, 0x0c, 0x00,
            0x21, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x21, 0x00, 0x00, 0x00, 0x64, 0x01,
            0x85, 0x0b, 0x6d, 0x74, 0x6c, 0x2d, 0x73, 0x72, 0x76, 0x2d, 0x61, 0x64, 0x32, 0x07,
            0x6c, 0x61, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
            0xc0, 0x47, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0xc0, 0xa8,
            0x02, 0xe6,
        ];

        let mut pkt = Dns::new(&packet);
        pkt.process_queries();

        assert_eq!(
            pkt.query_list[0].name, "_ldap._tcp.pdc._msdcs.lallier.local",
            "DNS question name"
        );
    }

    #[test]
    fn dns_process_query_1_reply() {
        let packet: Vec<u8> = vec![
            0x6d, 0xd, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x4, 0x70, 0x69, 0x63,
            0x6f, 0x3, 0x67, 0x74, 0x6d, 0x4, 0x65, 0x73, 0x65, 0x74, 0x3, 0x43, 0x4f, 0x4d, 0x0,
            0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x6, 0x0, 0x4, 0x26,
            0x5a, 0xe2, 0x24, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0,
        ];
        let mut pkt = Dns::new(&packet);
        pkt.offset = 35;
        pkt.process_answers();

        assert_eq!(
            pkt.answer_list[0].name, "pico.gtm.eset.COM",
            "DNS question name"
        );
    }
    #[test]
    fn dns_process_query_3_replies() {
        let packet: Vec<u8> = vec![
            0xd8, 0xd9, 0x81, 0x80, 0x0, 0x1, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x5, 0x73, 0x6c, 0x73,
            0x63, 0x72, 0x6, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x9, 0x6d, 0x69, 0x63, 0x72, 0x6f,
            0x73, 0x6f, 0x66, 0x74, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0,
            0x5, 0x0, 0x1, 0x0, 0x0, 0x7, 0x88, 0x0, 0x6, 0x3, 0x73, 0x6c, 0x73, 0xc0, 0x12, 0xc0,
            0x38, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0xc, 0xf3, 0x0, 0x2a, 0x3, 0x67, 0x6c, 0x62, 0x3,
            0x73, 0x6c, 0x73, 0x4, 0x70, 0x72, 0x6f, 0x64, 0x4, 0x64, 0x63, 0x61, 0x74, 0x3, 0x64,
            0x73, 0x70, 0xe, 0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x6d, 0x61, 0x6e, 0x61,
            0x67, 0x65, 0x72, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xc0, 0x4a, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0,
            0x0, 0x82, 0x0, 0x4, 0x14, 0x36, 0x59, 0x6a,
        ];

        let mut pkt = Dns::new(&packet);
        pkt.offset = 44;
        pkt.process_answers();

        assert_eq!(pkt.answer_list.len(), 3, "DNS question with 3 replies");
    }

    #[test]
    fn dns_process_query_4_replies() {
        let packet: Vec<u8> = vec![
            0x8, 0x7b, 0x81, 0x80, 0x0, 0x1, 0x0, 0x4, 0x0, 0x0, 0x0, 0x1, 0x9, 0x73, 0x63, 0x72,
            0x6f, 0x6f, 0x74, 0x63, 0x61, 0x32, 0x4, 0x6f, 0x63, 0x73, 0x70, 0xa, 0x73, 0x65, 0x63,
            0x6f, 0x6d, 0x74, 0x72, 0x75, 0x73, 0x74, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x0, 0x1, 0x0,
            0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x1, 0x1c, 0x0, 0x2a, 0x9, 0x73, 0x63,
            0x72, 0x6f, 0x6f, 0x74, 0x63, 0x61, 0x32, 0x4, 0x6f, 0x63, 0x73, 0x70, 0xa, 0x73, 0x65,
            0x63, 0x6f, 0x6d, 0x74, 0x72, 0x75, 0x73, 0x74, 0x3, 0x6e, 0x65, 0x74, 0x9, 0x65, 0x64,
            0x67, 0x65, 0x73, 0x75, 0x69, 0x74, 0x65, 0xc0, 0x26, 0xc0, 0x3b, 0x0, 0x5, 0x0, 0x1,
            0x0, 0x0, 0x22, 0xaa, 0x0, 0x11, 0x5, 0x61, 0x31, 0x36, 0x39, 0x32, 0x1, 0x62, 0x6,
            0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, 0xc0, 0x26, 0xc0, 0x71, 0x0, 0x1, 0x0, 0x1, 0x0,
            0x0, 0x0, 0x14, 0x0, 0x4, 0x42, 0x82, 0x3f, 0x31, 0xc0, 0x71, 0x0, 0x1, 0x0, 0x1, 0x0,
            0x0, 0x0, 0x14, 0x0, 0x4, 0x42, 0x82, 0x3f, 0x30, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0,
            0x80, 0x0, 0x0, 0x0,
        ];

        let mut pkt = Dns::new(&packet);
        pkt.offset = 47;
        pkt.process_answers();

        assert_eq!(pkt.answer_list.len(), 4, "DNS question with 4 replies");
        // assert_eq!(
        //     pkt.process_queries()[0].name,
        //     "_ldap._tcp.pdc._msdcs.lallier.local",
        //     "DNS question name"
        // );
    }

    #[test]
    fn dns_process_1_query_1_replies_1_additional() {
        let packet: Vec<u8> = vec![
            0x9, 0x30, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0xc, 0x73, 0x61, 0x66,
            0x65, 0x62, 0x72, 0x6f, 0x77, 0x73, 0x69, 0x6e, 0x67, 0xa, 0x67, 0x6f, 0x6f, 0x67,
            0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1,
            0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x11, 0x0, 0x4, 0xac, 0xd9, 0xd, 0x6a,
            0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0,
        ];

        let mut pkt = Dns::new(&packet);
        pkt.offset = 45;
        pkt.process_answers();

        assert_eq!(pkt.answer_list.len(), 1, "DNS answer 2 replies");
    }

    #[test]
    fn dns_process_dns_full() {
        let packet: Vec<u8> = vec![
            0x8, 0x7b, 0x81, 0x80, 0x0, 0x1, 0x0, 0x4, 0x0, 0x0, 0x0, 0x1, 0x9, 0x73, 0x63, 0x72,
            0x6f, 0x6f, 0x74, 0x63, 0x61, 0x32, 0x4, 0x6f, 0x63, 0x73, 0x70, 0xa, 0x73, 0x65, 0x63,
            0x6f, 0x6d, 0x74, 0x72, 0x75, 0x73, 0x74, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x0, 0x1, 0x0,
            0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x1, 0x1c, 0x0, 0x2a, 0x9, 0x73, 0x63,
            0x72, 0x6f, 0x6f, 0x74, 0x63, 0x61, 0x32, 0x4, 0x6f, 0x63, 0x73, 0x70, 0xa, 0x73, 0x65,
            0x63, 0x6f, 0x6d, 0x74, 0x72, 0x75, 0x73, 0x74, 0x3, 0x6e, 0x65, 0x74, 0x9, 0x65, 0x64,
            0x67, 0x65, 0x73, 0x75, 0x69, 0x74, 0x65, 0xc0, 0x26, 0xc0, 0x3b, 0x0, 0x5, 0x0, 0x1,
            0x0, 0x0, 0x22, 0xaa, 0x0, 0x11, 0x5, 0x61, 0x31, 0x36, 0x39, 0x32, 0x1, 0x62, 0x6,
            0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, 0xc0, 0x26, 0xc0, 0x71, 0x0, 0x1, 0x0, 0x1, 0x0,
            0x0, 0x0, 0x14, 0x0, 0x4, 0x42, 0x82, 0x3f, 0x31, 0xc0, 0x71, 0x0, 0x1, 0x0, 0x1, 0x0,
            0x0, 0x0, 0x14, 0x0, 0x4, 0x42, 0x82, 0x3f, 0x30, 0x0, 0x0, 0x29, 0x2, 0x0, 0x0, 0x0,
            0x80, 0x0, 0x0, 0x0,
        ];

        let mut pkt = Dns::new(&packet);
        pkt.decode();

        assert_eq!(pkt.answer_list.len(), 4, "Answers list 4 record");
        assert_eq!(pkt.query_list.len(), 1, "Questions list 1 query");
    }

    #[test]
    fn dns_process_srv_record() {
        let packet: Vec<u8> = vec![
            0x92, 0xdf, 0x85, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x5, 0x5f, 0x6c, 0x64,
            0x61, 0x70, 0x4, 0x5f, 0x74, 0x63, 0x70, 0x3, 0x70, 0x64, 0x63, 0x6, 0x5f, 0x6d, 0x73,
            0x64, 0x63, 0x73, 0x7, 0x6c, 0x61, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x5, 0x6c, 0x6f, 0x63,
            0x61, 0x6c, 0x0, 0x0, 0x21, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x21, 0x0, 0x1, 0x0, 0x0, 0x2,
            0x58, 0x0, 0x21, 0x0, 0x0, 0x0, 0x64, 0x1, 0x85, 0xb, 0x6d, 0x74, 0x6c, 0x2d, 0x73,
            0x72, 0x76, 0x2d, 0x61, 0x64, 0x32, 0x7, 0x6c, 0x61, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x5,
            0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x0, 0xc0, 0x47, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0xe, 0x10,
            0x0, 0x4, 0xc0, 0xa8, 0x2, 0xe6,
        ];

        let mut pkt = Dns::new(&packet);
        pkt.decode();

        assert_eq!(pkt.answer_list.len(), 1, "Answers list 1 SRV record");
        assert_eq!(pkt.answer_list[0].srv.port, 389, "SRV port == 389");
        assert_eq!(pkt.answer_list[0].srv.weight, 100, "SRV weigth == 100");
        assert_eq!(pkt.answer_list[0].srv.priority, 0, "SRV priority == 0");
    }

    #[test]
    fn dns_process_query_5_replies() {
        let packet: Vec<u8> = vec![
            0x2c, 0xa4, 0x81, 0x80, 0x0, 0x1, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x3, 0x77, 0x77, 0x77,
            0x4, 0x62, 0x69, 0x6e, 0x67, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc,
            0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x12, 0x16, 0x0, 0x2a, 0x6, 0x61, 0x2d, 0x30, 0x30, 0x30,
            0x31, 0xa, 0x61, 0x2d, 0x61, 0x66, 0x64, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x3, 0x6e, 0x65,
            0x74, 0xe, 0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x6d, 0x61, 0x6e, 0x61, 0x67,
            0x65, 0x72, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xc0, 0x2a, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0,
            0x3b, 0x0, 0x24, 0xc, 0x77, 0x77, 0x77, 0x2d, 0x62, 0x69, 0x6e, 0x67, 0x2d, 0x63, 0x6f,
            0x6d, 0xb, 0x64, 0x75, 0x61, 0x6c, 0x2d, 0x61, 0x2d, 0x30, 0x30, 0x30, 0x31, 0x8, 0x61,
            0x2d, 0x6d, 0x73, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x4f, 0xc0, 0x60, 0x0, 0x5, 0x0, 0x1,
            0x0, 0x0, 0x0, 0x23, 0x0, 0x2, 0xc0, 0x6d, 0xc0, 0x90, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0,
            0x0, 0x23, 0x0, 0x4, 0xcc, 0x4f, 0xc5, 0xc8, 0xc0, 0x90, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0,
            0x0, 0x23, 0x0, 0x4, 0xd, 0x6b, 0x15, 0xc8,
        ];

        println!("------------------------------------------");
        print_hex(packet.clone());
        let mut pkt = Dns::new(&packet);
        pkt.decode();
        // pkt.offset = 30;
        // pkt.process_answers();

        assert_eq!(pkt.answer_list.len(), 5, "DNS question with 5 replies");
        println!("Answer list: {:#?}", pkt.answer_list)
        // assert_eq!(
        //     pkt.process_queries()[0].name,
        //     "_ldap._tcp.pdc._msdcs.lallier.local",
        //     "DNS question name"
        // );
    }
    #[test]
    fn dns_query_rsig_answer() {
        let packet: Vec<u8> = vec![
            0xc0, 0xc, 0x0, 0x2e, 0x0, 0x1, 0x0, 0x0, 0x0, 0x17, 0x0, 0x5f, 0x0, 0x5, 0xd, 0x3,
            0x0, 0x0, 0x7, 0x8, 0x62, 0x38, 0xdf, 0xed, 0x62, 0x36, 0x3c, 0xed, 0x7a, 0xc5, 0x7,
            0x6e, 0x72, 0x2d, 0x64, 0x61, 0x74, 0x61, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xe8, 0xc8, 0x4b,
            0x1, 0x33, 0x7d, 0xed, 0x12, 0x6e, 0x10, 0xa, 0xb6, 0x90, 0xfa, 0x94, 0x22, 0x22, 0x9a,
            0x49, 0x47, 0x99, 0xbd, 0x7c, 0x48, 0xef, 0x9d, 0xc4, 0x7e, 0x60, 0x5f, 0xad, 0x17,
            0x14, 0x60, 0x9a, 0xd1, 0x15, 0x41, 0x4a, 0x79, 0xfd, 0xf7, 0xe3, 0x78, 0x8f, 0x50,
            0x53, 0xc0, 0x33, 0x66, 0x39, 0x26, 0xf3, 0xe0, 0x7d, 0x91, 0x42, 0xc3, 0x42, 0xf1,
            0x78, 0xe0, 0xf3, 0xc3,
        ];

        println!("------------------------------------------");
        print_hex(packet.clone());
        let mut answer = Answer::default();
        answer.decode(&packet, 0, 0xff);
        // pkt.offset = 30;
        // pkt.process_answers();

        assert_eq!(answer.rrsig.is_some(), true, "DNS rrsig present");
        assert_eq!(
            answer.rrsig.as_ref().unwrap().type_covered,
            5,
            "DNS rrsig type covered"
        );
        assert_eq!(
            answer.rrsig.as_ref().unwrap().orig_ttl,
            1800,
            "DNS rrsig type covered"
        );
        assert_eq!(
            answer.rrsig.as_ref().unwrap().algorithm,
            13,
            "DNS rrsig type covered"
        );
        println!("{}", answer.rrsig.unwrap());
        // println!("Answer list: {:#?}", pkt.answer_list)
        // assert_eq!(
        //     pkt.answer_list[2].rrsig.is_some(),
        //     true,
        //     "DNS rrsig present"
        // );
    }
}
