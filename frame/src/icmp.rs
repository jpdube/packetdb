use crate::fields;
use crate::layer::Layer;
use crate::packet_display::PacketDisplay;

use byteorder::{BigEndian, ByteOrder};
/*
Echo or Echo Reply Message

  0               1               2               3
  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |     Type      |     Code      |          Checksum             |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Identifier          |        Sequence Number        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |     Data ...
 +-+-+-+-+-
IP Fields:

   Addresses

      The address of the source in an echo message will be the
      destination of the echo reply message.  To form an echo reply
      message, the source and destination addresses are simply reversed,
      the type code changed to 0, and the checksum recomputed.

   IP Fields:

   Type

      8 for echo message;

      0 for echo reply message.

   Code

      0

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      If the total length is odd, the received data is padded with one
      octet of zeros for computing the checksum.  This checksum may be
      replaced in the future.

   Identifier

      If code = 0, an identifier to aid in matching echos and replies,
      may be zero.

   Sequence Number

      If code = 0, a sequence number to aid in matching echos and
      replies, may be zero.

   Description

      The data received in the echo message must be returned in the echo
      reply message.

      The identifier and sequence number may be used by the echo sender
      to aid in matching the replies with the echo requests.  For
      example, the identifier might be used like a port in TCP or UDP to
      identify a session, and the sequence number might be incremented
      on each echo request sent.  The echoer returns these same values
      in the echo reply.

      Code 0 may be received from a gateway or a host.
*/

// #[derive(Default, Debug, Clone)]
// pub struct ICMPBuilder {
//     raw_packet: Vec<u8>,
// }

// impl ICMPBuilder {

//     pub fn set_packet(&mut self, packet: Vec<u8>) {
//         self.raw_packet = packet;
//     }

//     pub fn get_field(&self, field: &str) -> usize {
//         match field {
//             "icmp.type" => self.itype() as usize,
//             "icmp.code" => self.code() as usize,
//             "icmp.identifier" => self.identifier() as usize,
//             "icmp.seq_no" => self.seq_no() as usize,
//             _ => 0xffff,
//         }
//     }

//     pub fn itype(&self) -> u8 {
//         self.raw_packet[0]
//     }
// }

#[derive(Default, Debug, Clone)]
pub struct Icmp {
    raw_packet: Vec<u8>,
}

impl Icmp {
    pub fn set_packet(&mut self, packet: Vec<u8>) {
        self.raw_packet = packet;
    }

    pub fn itype(&self) -> u8 {
        self.raw_packet[0]
    }

    pub fn code(&self) -> u8 {
        self.raw_packet[1]
    }

    pub fn checksum(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[2..4])
    }

    pub fn identifier(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[4..6])
    }

    pub fn seq_no(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[6..8])
    }

    pub fn payload_range(&self, offset: usize, len: usize) -> Vec<u8> {
        self.raw_packet[offset..offset + len].to_vec()
    }
}

impl Layer for Icmp {
    fn get_field(&self, field: u32) -> usize {
        match field {
            fields::ICMP_TYPE => self.itype() as usize,
            fields::ICMP_CODE => self.code() as usize,
            fields::ICMP_IDENTIFIER => self.identifier() as usize,
            fields::ICMP_SEQ_NO => self.seq_no() as usize,
            _ => 0xffff,
        }
    }

    fn get_field_bytes(&self, _field_name: u32) -> Option<Vec<u8>> {
        None
    }

    fn get_name(&self) -> String {
        return "icmp".to_string();
    }
}

impl PacketDisplay for Icmp {
    fn summary(&self) -> String {
        let result: String;

        result = format!(
            "ICMP Echo -> Type: {}, Code: {}, Seq: {}",
            self.itype(),
            self.code(),
            self.seq_no(),
        );

        result
    }

    fn show_detail(&self) -> String {
        "ICMP Echo Detail".to_string()
    }
}
