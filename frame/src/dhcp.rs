use crate::layer::Layer;
use byteorder::{BigEndian, ByteOrder};
use std::fmt;
use std::str;

use crate::fields;
use crate::pfield::{Field, FieldType};
use crate::print_hex::print_hex;
use crate::{ipv4_address::IPv4, mac_address::MacAddr};

const SERVER_NAME_OFFSET: usize = 0x2c;
const BOOT_FILE_OFFSET: usize = 0x6c;

const OPTIONS_MSG_TYPE: u8 = 0x35;
const OPTIONS_CLIENT_ID: u8 = 0x3d;
const OPTIONS_REQUESTED_IP_ADDR: u8 = 0x32;
const OPTIONS_HOSTNAME: u8 = 0x0c;
const OPTIONS_CLIENT_FQDN: u8 = 0x51;
const OPTIONS_VENDOR_CLASSIFIER: u8 = 0x3c;
const OPTIONS_PARAMS_REQ_LIST: u8 = 0x37;

const OPTIONS_DHCP_SERVER_ID: u8 = 0x36;
const OPTIONS_DHCP_SUBNET_MASK: u8 = 0x01;
const OPTIONS_DHCP_VENDOR_INFO: u8 = 0x2b;
const OPTIONS_DHCP_ROUTER: u8 = 0x03;
const OPTIONS_DHCP_DOMAIN_NAME_SERVER: u8 = 0x06;
const OPTIONS_DHCP_DOMAIN_NAME: u8 = 0x0f;
const OPTIONS_DHCP_RENEWAL_TIME: u8 = 0x3a;
const OPTIONS_DHCP_REBINDING_TIME: u8 = 0x3b;
const OPTIONS_DHCP_IP_LEASE_TIME: u8 = 0x33;

const OPTIONS_END: u8 = 0xff;

#[derive(Debug, Clone)]
struct IpAddrLeaseTime {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl IpAddrLeaseTime {
    pub fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> u32 {
        BigEndian::read_u32(&self._raw_data[0..self._length as usize])
    }
}

#[derive(Debug, Clone)]
struct RebindingTime {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl RebindingTime {
    pub fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> u32 {
        BigEndian::read_u32(&self._raw_data[0..self._length as usize])
    }
}

#[derive(Debug, Clone)]
struct RenewalTime {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl RenewalTime {
    pub fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> u32 {
        BigEndian::read_u32(&self._raw_data[0..self._length as usize])
    }
}

#[derive(Debug, Clone)]
struct DomainName {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl DomainName {
    fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> String {
        str::from_utf8(&self._raw_data[0..0 + (self._length as usize) - 1])
            .unwrap()
            .to_string()
    }
}

#[derive(Debug, Clone)]
struct Router {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl Router {
    pub fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> u32 {
        BigEndian::read_u32(&self._raw_data[0..self._length as usize])
    }
}

#[derive(Debug, Clone)]
struct SubnetMask {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl SubnetMask {
    pub fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> u32 {
        BigEndian::read_u32(&self._raw_data[0..self._length as usize])
    }
}

#[derive(Debug, Clone)]
struct DHCPServerID {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl DHCPServerID {
    pub fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> u32 {
        BigEndian::read_u32(&self._raw_data[0..self._length as usize])
    }
}

#[derive(Debug, Clone)]
struct RequestedIPAddr {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl RequestedIPAddr {
    pub fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> u32 {
        BigEndian::read_u32(&self._raw_data[0..self._length as usize])
    }
}

#[derive(Default, Debug, Clone)]
struct DhcpOption {
    id: u8,
    length: usize,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MsgType {
    _length: u8,
    request: u8,
}

impl MsgType {
    pub fn new(length: u8, option_data: &[u8]) -> Self {
        Self {
            _length: length,
            request: option_data[0],
        }
    }

    pub fn msg_type(&self) -> u8 {
        self.request
    }
}

#[derive(Debug, Clone)]
struct ClientIdentifier {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl ClientIdentifier {
    fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn hwnd_type(&self) -> u8 {
        self._raw_data[0]
    }

    pub fn mac_addr(&self) -> u64 {
        BigEndian::read_u48(&self._raw_data[1..7]) as u64
    }
}

#[derive(Debug, Clone)]
struct Hostname {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl Hostname {
    fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> String {
        str::from_utf8(&self._raw_data[0..0 + self._length as usize])
            .unwrap()
            .to_string()
    }
}

#[derive(Default, Debug, Clone)]
struct ClientFQDN {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl ClientFQDN {
    fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn flags(&self) -> u8 {
        self._raw_data[0]
    }

    pub fn a_rr_result(&self) -> u8 {
        self._raw_data[1]
    }

    pub fn ptr_rr_result(&self) -> u8 {
        self._raw_data[2]
    }

    pub fn client_name(&self) -> String {
        str::from_utf8(&self._raw_data[3..3 + (self._length - 3) as usize])
            .unwrap()
            .to_string()
    }
}

#[derive(Default, Debug, Clone)]
struct DomainNameServer {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl DomainNameServer {
    fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn dns_ip(&self) -> Vec<u32> {
        let mut offset = 0;
        let mut dns_list: Vec<u32> = Vec::new();

        for _ in 0..(self._length as usize) / 4 {
            dns_list.push(BigEndian::read_u32(&self._raw_data[offset..offset + 4]));
            offset += 4;
        }

        dns_list
    }
}
#[derive(Default, Debug, Clone)]
struct VendorClassID {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl VendorClassID {
    fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> String {
        str::from_utf8(&self._raw_data[0..0 + (self._length) as usize])
            .unwrap()
            .to_string()
    }
}

#[derive(Default, Debug, Clone)]
struct VendorInfo {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl VendorInfo {
    fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> Vec<u8> {
        self._raw_data[0..0 + (self._length) as usize].to_vec()
    }
}

#[derive(Default, Debug, Clone)]
struct ParameterRequestList {
    _length: u8,
    _raw_data: Vec<u8>,
}

impl ParameterRequestList {
    fn new(length: u8, raw_data: &[u8]) -> Self {
        Self {
            _length: length,
            _raw_data: raw_data.to_vec(),
        }
    }

    pub fn value(&self) -> Vec<u8> {
        self._raw_data.clone()
    }
}

impl fmt::Display for ParameterRequestList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Params List: {:?}", self._raw_data)
    }
}

#[derive(Debug, Clone)]
pub struct Dhcp<'a> {
    raw_data: &'a [u8],
    option_index: usize,
    magic_no: u32,
    param_req_list: Option<ParameterRequestList>,
    vendor_class_id: Option<VendorClassID>,
    client_fqdn: Option<ClientFQDN>,
    hostname: Option<Hostname>,
    client_id: Option<ClientIdentifier>,
    msg_type: Option<MsgType>,
    requested_ip_addr: Option<RequestedIPAddr>,
    server_id: Option<DHCPServerID>,
    subnet_mask: Option<SubnetMask>,
    router: Option<Router>,
    vendor_info: Option<VendorInfo>,
    dns_server: Option<DomainNameServer>,
    domain_name: Option<DomainName>,
    renewal_time: Option<RenewalTime>,
    rebinding_time: Option<RebindingTime>,
    ip_addr_lease_time: Option<IpAddrLeaseTime>,
}

impl<'a> fmt::Display for Dhcp<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Op code: {}, Hdr type: {}, Hdr len: {},  XID: {:x}, CI Addr: {}, You IP addr: {}, Server IP: {}, Relay IP: {}, Hwd address: {}, Params list: {:?}, Vendor class ID: {:?}", 
            self.op(),
            self.htype(),
            self.hlen(),
            self.xid(),
            IPv4::new(self.ciaddr(), 32),
            IPv4::new(self.yiaddr(), 32),
            IPv4::new(self.siaddr(), 32),
            IPv4::new(self.giaddr(), 32),
            self.chaddr(),
            self.param_req_list,
            self.vendor_class_id,
        )
    }
}

impl<'a> Dhcp<'a> {
    pub fn new(raw_data: &'a [u8]) -> Self {
        let mut my_self = Self {
            raw_data,
            option_index: 240,
            magic_no: 0,
            param_req_list: None,
            vendor_class_id: None,
            client_fqdn: None,
            hostname: None,
            client_id: None,
            msg_type: None,
            requested_ip_addr: None,
            server_id: None,
            subnet_mask: None,
            router: None,
            vendor_info: None,
            dns_server: None,
            domain_name: None,
            renewal_time: None,
            rebinding_time: None,
            ip_addr_lease_time: None,
        };

        my_self.get_options();

        my_self
    }

    pub fn op(&self) -> u8 {
        self.raw_data[0] as u8
    }

    pub fn htype(&self) -> u8 {
        self.raw_data[1] as u8
    }

    pub fn hlen(&self) -> u8 {
        self.raw_data[2] as u8
    }

    pub fn hops(&self) -> u8 {
        self.raw_data[3] as u8
    }

    pub fn xid(&self) -> u32 {
        BigEndian::read_u32(&self.raw_data[4..8])
    }

    pub fn secs(&self) -> u16 {
        BigEndian::read_u16(&self.raw_data[8..10])
    }

    pub fn flags(&self) -> u16 {
        BigEndian::read_u16(&self.raw_data[10..12])
    }

    pub fn ciaddr(&self) -> u32 {
        BigEndian::read_u32(&self.raw_data[12..16])
    }

    pub fn yiaddr(&self) -> u32 {
        BigEndian::read_u32(&self.raw_data[16..20])
    }

    pub fn siaddr(&self) -> u32 {
        BigEndian::read_u32(&self.raw_data[20..24])
    }

    pub fn giaddr(&self) -> u32 {
        BigEndian::read_u32(&self.raw_data[24..28])
    }

    pub fn chaddr(&self) -> MacAddr {
        MacAddr::set_from_int(&(BigEndian::read_u48(&self.raw_data[28..34]) as u64))
    }

    pub fn server_name(&self) -> String {
        self.get_name(SERVER_NAME_OFFSET)
    }

    pub fn boot_file_name(&self) -> String {
        self.get_name(BOOT_FILE_OFFSET)
    }

    pub fn ip_lease_time(&self, field: &u32) -> Option<Field> {
        if let Some(ip_lease) = &self.ip_addr_lease_time {
            Some(Field::set_field(
                FieldType::TimeValue(ip_lease.value()),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn rebinding_time(&self, field: &u32) -> Option<Field> {
        if let Some(rebind_time) = &self.rebinding_time {
            Some(Field::set_field(
                FieldType::TimeValue(rebind_time.value()),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn renewal_time(&self, field: &u32) -> Option<Field> {
        if let Some(renewal_time) = &self.renewal_time {
            Some(Field::set_field(
                FieldType::TimeValue(renewal_time.value()),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn domain_name(&self, field: &u32) -> Option<Field> {
        if let Some(domain_name) = &self.domain_name {
            Some(Field::set_field(
                FieldType::String(domain_name.value()),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn client_ip(&self, field: &u32) -> Option<Field> {
        Some(Field::set_field(FieldType::Ipv4(self.ciaddr(), 32), *field))
    }

    pub fn domain_servers(&self, field: &u32) -> Option<Field> {
        if let Some(iplt) = &self.dns_server {
            let mut field_list: Vec<Box<FieldType>> = Vec::new();

            for ip in iplt.dns_ip() {
                field_list.push(Box::new(FieldType::Ipv4(ip, 32)));
            }

            Some(Field::set_field(FieldType::FieldArray(field_list), *field))
        } else {
            None
        }
    }

    pub fn router(&self, field: &u32) -> Option<Field> {
        if let Some(router) = &self.router {
            Some(Field::set_field(
                FieldType::Ipv4(router.value(), 32),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn subnet_mask(&self, field: &u32) -> Option<Field> {
        if let Some(mask) = &self.subnet_mask {
            Some(Field::set_field(FieldType::Ipv4(mask.value(), 32), *field))
        } else {
            None
        }
    }

    pub fn server_id(&self, field: &u32) -> Option<Field> {
        if let Some(srv) = &self.server_id {
            Some(Field::set_field(FieldType::Ipv4(srv.value(), 32), *field))
        } else {
            None
        }
    }

    pub fn requested_id(&self, field: &u32) -> Option<Field> {
        if let Some(req_ip) = &self.requested_ip_addr {
            Some(Field::set_field(
                FieldType::Ipv4(req_ip.value(), 32),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn client_id_hwnd_type(&self, field: &u32) -> Option<Field> {
        if let Some(client_id) = &self.client_id {
            Some(Field::set_field(
                FieldType::Int8(client_id.hwnd_type()),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn client_id_mac_addr(&self, field: &u32) -> Option<Field> {
        if let Some(client_id) = &self.client_id {
            Some(Field::set_field(
                FieldType::MacAddr(client_id.mac_addr()),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn hostname(&self, field: &u32) -> Option<Field> {
        if let Some(hostname) = &self.hostname {
            Some(Field::set_field(
                FieldType::String(hostname.value()),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn client_fqdn_flags(&self, field: &u32) -> Option<Field> {
        if let Some(client_id) = &self.client_fqdn {
            Some(Field::set_field(FieldType::Int8(client_id.flags()), *field))
        } else {
            None
        }
    }

    pub fn client_fqdn_a_result(&self, field: &u32) -> Option<Field> {
        if let Some(client_id) = &self.client_fqdn {
            Some(Field::set_field(
                FieldType::Int8(client_id.a_rr_result()),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn client_fqdn_ptr_rr_result(&self, field: &u32) -> Option<Field> {
        if let Some(client_id) = &self.client_fqdn {
            Some(Field::set_field(
                FieldType::Int8(client_id.ptr_rr_result()),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn client_fqdn_name(&self, field: &u32) -> Option<Field> {
        if let Some(client_id) = &self.client_fqdn {
            Some(Field::set_field(
                FieldType::String(client_id.client_name()),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn vendor_class_id(&self, field: &u32) -> Option<Field> {
        if let Some(vendor) = &self.vendor_class_id {
            Some(Field::set_field(FieldType::String(vendor.value()), *field))
        } else {
            None
        }
    }

    pub fn vendor_info(&self, field: &u32) -> Option<Field> {
        if let Some(vendor) = &self.vendor_info {
            Some(Field::set_field(
                FieldType::ByteArray(vendor.value()),
                *field,
            ))
        } else {
            None
        }
    }

    pub fn param_req_list(&self, field: &u32) -> Option<Field> {
        if let Some(params) = &self.param_req_list {
            Some(Field::set_field(
                FieldType::ByteArray(params.value()),
                *field,
            ))
        } else {
            None
        }
    }

    //-------------------------------------------------------------
    fn get_name(&self, offset: usize) -> String {
        let mut index = 0;
        let mut current_char: u8;

        print_hex(self.raw_data.to_vec());

        loop {
            current_char = self.raw_data[offset + index];
            if current_char == 0x00 {
                break;
            }

            index += 1;
            if (offset + index) > self.raw_data.len() {
                break;
            }
        }

        if index > 0 {
            str::from_utf8(&self.raw_data[offset..offset + index])
                .unwrap()
                .to_string()
        } else {
            String::new()
        }
    }

    fn fetch(&mut self) -> Option<DhcpOption> {
        let mut options = DhcpOption::default();

        if self.option_index + 1 < self.raw_data.len() {
            options.id = self.raw_data[self.option_index];

            self.option_index += 1;
            options.length = self.raw_data[self.option_index] as usize;

            self.option_index += 1;
            options.data =
                self.raw_data[self.option_index..self.option_index + options.length].to_vec();

            self.option_index += options.length;

            return Some(options);
        }

        None
    }

    pub fn get_options(&mut self) {
        self.magic_no = BigEndian::read_u32(&self.raw_data[0xec..0xec + 4]);

        while let Some(options) = self.fetch() {
            // println!("---> Options: {:?} magic no: {:x}", options, self.magic_no);
            match options.id {
                OPTIONS_MSG_TYPE => {
                    self.msg_type = Some(MsgType::new(options.length as u8, &options.data));
                }

                OPTIONS_CLIENT_ID => {
                    self.client_id =
                        Some(ClientIdentifier::new(options.length as u8, &options.data));
                }

                OPTIONS_HOSTNAME => {
                    self.hostname = Some(Hostname::new(options.length as u8, &options.data));
                }

                OPTIONS_VENDOR_CLASSIFIER => {
                    self.vendor_class_id =
                        Some(VendorClassID::new(options.length as u8, &options.data));
                }

                OPTIONS_CLIENT_FQDN => {
                    self.client_fqdn = Some(ClientFQDN::new(options.length as u8, &options.data));
                }

                OPTIONS_REQUESTED_IP_ADDR => {
                    self.requested_ip_addr =
                        Some(RequestedIPAddr::new(options.length as u8, &options.data));
                }
                OPTIONS_PARAMS_REQ_LIST => {
                    self.param_req_list = Some(ParameterRequestList::new(
                        options.length as u8,
                        &options.data,
                    ));
                }
                OPTIONS_DHCP_SERVER_ID => {
                    self.server_id = Some(DHCPServerID::new(options.length as u8, &options.data));
                }

                OPTIONS_DHCP_SUBNET_MASK => {
                    self.subnet_mask = Some(SubnetMask::new(options.length as u8, &options.data));
                }

                OPTIONS_DHCP_ROUTER => {
                    self.router = Some(Router::new(options.length as u8, &options.data));
                }

                OPTIONS_DHCP_VENDOR_INFO => {
                    self.vendor_info = Some(VendorInfo::new(options.length as u8, &options.data));
                }

                OPTIONS_DHCP_DOMAIN_NAME_SERVER => {
                    self.dns_server =
                        Some(DomainNameServer::new(options.length as u8, &options.data));
                }

                OPTIONS_DHCP_DOMAIN_NAME => {
                    self.domain_name = Some(DomainName::new(options.length as u8, &options.data));
                }

                OPTIONS_DHCP_RENEWAL_TIME => {
                    self.renewal_time = Some(RenewalTime::new(options.length as u8, &options.data));
                }

                OPTIONS_DHCP_REBINDING_TIME => {
                    self.rebinding_time =
                        Some(RebindingTime::new(options.length as u8, &options.data));
                }

                OPTIONS_DHCP_IP_LEASE_TIME => {
                    self.ip_addr_lease_time =
                        Some(IpAddrLeaseTime::new(options.length as u8, &options.data));
                }

                OPTIONS_END => break,
                _ => break,
            }
        }
    }
}

impl<'a> Layer for Dhcp<'a> {
    fn get_name(&self) -> String {
        "dhcp".to_string()
    }

    fn get_field(&self, field: u32) -> Option<Field> {
        match field {
            fields::DHCP_OPCODE => Some(Field::set_field(FieldType::Int8(self.op()), field)),
            fields::DHCP_XID => Some(Field::set_field(FieldType::Int32(self.xid()), field)),
            fields::DHCP_CLIENT_IP => self.client_ip(&field),
            fields::DHCP_IP_LEASE_TIME => self.ip_lease_time(&field),
            fields::DHCP_REBINDING_TIME => self.rebinding_time(&field),
            fields::DHCP_RENEWAL_TIME => self.renewal_time(&field),
            fields::DHCP_DOMAIN_NAME => self.domain_name(&field),
            fields::DHCP_DOMAIN_SRV => self.domain_servers(&field),
            fields::DHCP_ROUTER => self.router(&field),
            fields::DHCP_SUBNET_MASK => self.subnet_mask(&field),
            fields::DHCP_SERVER_ID => self.server_id(&field),
            fields::DHCP_REQUESTED_IP => self.requested_id(&field),
            fields::DHCP_CLIENT_ID_HWND_TYPE => self.client_id_hwnd_type(&field),
            fields::DHCP_CLIENT_ID_MAC => self.client_id_mac_addr(&field),
            fields::DHCP_HOSTNAME => self.hostname(&field),
            fields::DHCP_CLIENT_FQDN_FLAGS => self.client_fqdn_flags(&field),
            fields::DHCP_CLIENT_FQDN_A_RESULT => self.client_fqdn_a_result(&field),
            fields::DHCP_CLIENT_FQDN_PTR_RESULT => self.client_fqdn_ptr_rr_result(&field),
            fields::DHCP_CLIENT_FQDN_NAME => self.client_fqdn_name(&field),
            fields::DHCP_VENDOR_CLASS_ID => self.vendor_class_id(&field),
            fields::DHCP_VENDOR_INFO => self.vendor_info(&field),
            fields::DHCP_PARAMS_REQ_LIST => self.param_req_list(&field),

            _ => None,
        }
    }

    fn get_field_bytes(&self, _field_name: u32) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_header_decode() {
        let packet: Vec<u8> = vec![
            0x2, 0x1, 0x6, 0x0, 0x27, 0x91, 0x25, 0x32, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xc0, 0xa8, 0x3, 0x82, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb8, 0x85, 0x84, 0x9a,
            0xf0, 0x17, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x63, 0x82, 0x53, 0x63, 0x35, 0x1, 0x5, 0x3a, 0x4, 0x0, 0x3, 0xf4, 0x80, 0x3b, 0x4,
            0x0, 0x6, 0xeb, 0xe0, 0x33, 0x4, 0x0, 0x7, 0xe9, 0x0, 0x36, 0x4, 0xc0, 0xa8, 0x3, 0xe6,
            0x1, 0x4, 0xff, 0xff, 0xff, 0x0, 0x51, 0x3, 0x3, 0xff, 0x0, 0x3, 0x4, 0xc0, 0xa8, 0x3,
            0x1, 0x6, 0x8, 0xc0, 0xa8, 0x3, 0xe6, 0xc0, 0xa8, 0x2, 0xe6, 0xf, 0xe, 0x6c, 0x61,
            0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x0, 0xff,
        ];

        let dhcp = Dhcp::new(&packet);

        assert_eq!(dhcp.op(), 0x02, "DHCP op code");
        assert_eq!(dhcp.htype(), 0x01, "DHCP hardware type");
        assert_eq!(dhcp.hlen(), 6, "DHCP hardwarw length");
        assert_eq!(dhcp.xid(), 0x27912532, "DHCP transaction ID");
        assert_eq!(dhcp.secs(), 0x0, "DHCP seconds");
        assert_eq!(dhcp.flags(), 0x0, "DHCP Bootp flags");
        assert_eq!(dhcp.ciaddr(), 0, "DHCP client IP");
        // assert_eq!(dhcp.server_name(), "", "DHCP server name");

        println!("DHCP: {}", dhcp);
    }

    #[test]
    fn dhcp_server_name() {
        let packet: Vec<u8> = vec![
            0x2, 0x1, 0x6, 0x0, 0x74, 0x71, 0x72, 0xf6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xc0, 0xa8, 0x3, 0x82, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb8, 0x85, 0x84, 0x9a,
            0xf0, 0x17, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0x42, 0x43, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x46, 0x47, 0x48, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x63, 0x82, 0x53, 0x63, 0x35, 0x1, 0x5, 0x3a, 0x4, 0x0, 0x3, 0xf4, 0x80, 0x3b,
            0x4, 0x0, 0x6, 0xeb, 0xe0, 0x33, 0x4, 0x0, 0x7, 0xe9, 0x0, 0x36, 0x4, 0xc0, 0xa8, 0x3,
            0xe6, 0x1, 0x4, 0xff, 0xff, 0xff, 0x0, 0x51, 0x3, 0x3, 0xff, 0x0, 0x3, 0x4, 0xc0, 0xa8,
            0x3, 0x1, 0x6, 0x8, 0xc0, 0xa8, 0x3, 0xe6, 0xc0, 0xa8, 0x2, 0xe6, 0xf, 0xe, 0x6c, 0x61,
            0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x0, 0xff,
        ];

        let dhcp = Dhcp::new(&packet);

        assert_eq!(dhcp.server_name(), "ABC", "DHCP server name");

        println!("DHCP: {}", dhcp);
    }

    #[test]
    fn dhcp_boot_file_name() {
        let packet: Vec<u8> = vec![
            0x2, 0x1, 0x6, 0x0, 0x74, 0x71, 0x72, 0xf6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xc0, 0xa8, 0x3, 0x82, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb8, 0x85, 0x84, 0x9a,
            0xf0, 0x17, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0x42, 0x43, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x46, 0x47, 0x48, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x63, 0x82, 0x53, 0x63, 0x35, 0x1, 0x5, 0x3a, 0x4, 0x0, 0x3, 0xf4, 0x80, 0x3b,
            0x4, 0x0, 0x6, 0xeb, 0xe0, 0x33, 0x4, 0x0, 0x7, 0xe9, 0x0, 0x36, 0x4, 0xc0, 0xa8, 0x3,
            0xe6, 0x1, 0x4, 0xff, 0xff, 0xff, 0x0, 0x51, 0x3, 0x3, 0xff, 0x0, 0x3, 0x4, 0xc0, 0xa8,
            0x3, 0x1, 0x6, 0x8, 0xc0, 0xa8, 0x3, 0xe6, 0xc0, 0xa8, 0x2, 0xe6, 0xf, 0xe, 0x6c, 0x61,
            0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x0, 0xff,
        ];

        let mut dhcp = Dhcp::new(&packet);
        dhcp.get_options();

        assert_eq!(dhcp.boot_file_name(), "FGH", "DHCP server name");

        println!("DHCP: {}", dhcp);
    }

    #[test]
    fn dhcp_vendor_class_id() {
        let packet: Vec<u8> = vec![0x4d, 0x53, 0x46, 0x54, 0x20, 0x35, 0x2e, 0x30];

        let dhcp = VendorClassID::new(8, &packet);

        assert_eq!(dhcp.value(), "MSFT 5.0", "Options vendor class id");
    }

    #[test]
    fn dhcp_hostname() {
        let packet: Vec<u8> = vec![
            0x68, 0x75, 0x6c, 0x6c, 0x2d, 0x70, 0x63, 0x2d, 0x76, 0x74, 0x73, 0x2d, 0x31, 0x36,
        ];

        let dhcp = Hostname::new(0xe, &packet);

        assert_eq!(dhcp.value(), "hull-pc-vts-16", "Options hostname");
    }

    #[test]
    fn dhcp_client_identifier() {
        let packet: Vec<u8> = vec![0x1, 0xb8, 0x85, 0x84, 0x9a, 0xf0, 0x17];

        let dhcp = ClientIdentifier::new(7, &packet);

        assert_eq!(dhcp.hwnd_type(), 1, "Options client id Hardware type");
        assert_eq!(dhcp.mac_addr(), 0xb885849af017, "Options client mac addr");
    }

    #[test]
    fn dhcp_client_fqdn() {
        let packet: Vec<u8> = vec![
            0x0, 0x0, 0x0, 0x68, 0x75, 0x6c, 0x6c, 0x2d, 0x70, 0x63, 0x2d, 0x76, 0x74, 0x73, 0x2d,
            0x31, 0x36, 0x2e, 0x6c, 0x61, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e, 0x6c, 0x6f, 0x63,
            0x61, 0x6c,
        ];

        let dhcp = ClientFQDN::new(31, &packet);

        assert_eq!(dhcp.flags(), 0x0, "Options client flags");
        assert_eq!(dhcp.a_rr_result(), 0x0, "Options client a result");
        assert_eq!(dhcp.ptr_rr_result(), 0x0, "Options client ptr result");
        assert_eq!(
            dhcp.client_name(),
            "hull-pc-vts-16.lallier.local",
            "Options client fqdn"
        );
    }

    #[test]
    fn dhcp_requested_ip() {
        let packet: Vec<u8> = vec![0xc0, 0xa8, 0x3, 0x82];

        let dhcp = RequestedIPAddr::new(4, &packet);

        assert_eq!(dhcp.value(), 0xc0a80382, "Options client requested ip");
    }

    #[test]
    fn dhcp_options() {
        //--- File 1556.pcap
        let packet: Vec<u8> = vec![
            0x1, 0x1, 0x6, 0x0, 0x74, 0x71, 0x72, 0xf6, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb8, 0x85, 0x84, 0x9a,
            0xf0, 0x17, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x63, 0x82, 0x53, 0x63, 0x35, 0x1, 0x3, 0x3d, 0x7, 0x1, 0xb8, 0x85, 0x84, 0x9a, 0xf0,
            0x17, 0x32, 0x4, 0xc0, 0xa8, 0x3, 0x82, 0xc, 0xe, 0x68, 0x75, 0x6c, 0x6c, 0x2d, 0x70,
            0x63, 0x2d, 0x76, 0x74, 0x73, 0x2d, 0x31, 0x36, 0x51, 0x1f, 0x0, 0x0, 0x0, 0x68, 0x75,
            0x6c, 0x6c, 0x2d, 0x70, 0x63, 0x2d, 0x76, 0x74, 0x73, 0x2d, 0x31, 0x36, 0x2e, 0x6c,
            0x61, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x3c, 0x8,
            0x4d, 0x53, 0x46, 0x54, 0x20, 0x35, 0x2e, 0x30, 0x37, 0xe, 0x1, 0x3, 0x6, 0xf, 0x1f,
            0x21, 0x2b, 0x2c, 0x2e, 0x2f, 0x77, 0x79, 0xf9, 0xfc, 0xff,
        ];

        print_hex(packet.clone());

        let mut dhcp = Dhcp::new(&packet);
        dhcp.get_options();

        assert_eq!(
            dhcp.msg_type.is_some(),
            true,
            "DHCP option message type is present"
        );
        assert_eq!(
            dhcp.msg_type.unwrap().request,
            3,
            "DHCP option message type"
        );
        assert_eq!(dhcp.client_id.is_some(), true, "DHCP option client ID");
        assert_eq!(
            dhcp.client_id.unwrap().mac_addr(),
            0xb885849af017,
            "DHCP option client mac address"
        );
        assert_eq!(
            dhcp.requested_ip_addr.is_some(),
            true,
            "DHCP option requested ip present"
        );
        assert_eq!(
            dhcp.requested_ip_addr.unwrap().value(),
            0xc0a80382,
            "DHCP option requested ip"
        );

        // println!("DHCP: {}", dhcp);
    }

    #[test]
    fn dhcp_ack_options() {
        //--- File 1556.pcap ID: 0x1bb2e5e1
        let packet: Vec<u8> = vec![
            0x2, 0x1, 0x6, 0x0, 0x1b, 0xb2, 0xe5, 0xe1, 0x0, 0x0, 0x80, 0x0, 0xc0, 0xa8, 0x3, 0x82,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb8, 0x85, 0x84, 0x9a,
            0xf0, 0x17, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x63, 0x82, 0x53, 0x63, 0x35, 0x1, 0x5, 0x36, 0x4, 0xc0, 0xa8, 0x3, 0xe6, 0x1, 0x4,
            0xff, 0xff, 0xff, 0x0, 0x2b, 0x5, 0xdc, 0x3, 0x4e, 0x41, 0x50, 0x3, 0x4, 0xc0, 0xa8,
            0x3, 0x1, 0x6, 0x8, 0xc0, 0xa8, 0x3, 0xe6, 0xc0, 0xa8, 0x2, 0xe6, 0xf, 0xe, 0x6c, 0x61,
            0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x0, 0xff, 0x0, 0x0,
            0x0, 0x0, 0x0,
        ];

        print_hex(packet.clone());

        let mut dhcp = Dhcp::new(&packet);
        dhcp.get_options();

        assert_eq!(
            dhcp.msg_type.is_some(),
            true,
            "DHCP option message type is present"
        );

        assert_eq!(
            dhcp.msg_type.unwrap().request,
            5,
            "DHCP option message type"
        );

        assert_eq!(dhcp.server_id.is_some(), true, "Server ID is present");
        assert_eq!(dhcp.server_id.unwrap().value(), 0xc0a803e6, "Server ID");

        assert_eq!(dhcp.subnet_mask.is_some(), true, "Subnet mask is present");
        assert_eq!(dhcp.subnet_mask.unwrap().value(), 0xffffff00, "IP Mask");

        assert_eq!(dhcp.vendor_info.is_some(), true, "Vendor info is present");
        assert_eq!(
            dhcp.vendor_info.unwrap().vendor_info(),
            vec![0xdc, 0x03, 0x4e, 0x41, 0x50],
            "Vendor info value"
        );

        assert_eq!(dhcp.router.is_some(), true, "Router present");
        assert_eq!(dhcp.router.unwrap().value(), 0xc0a80301, "Router IP");

        assert_eq!(dhcp.dns_server.is_some(), true, "DNS name present");
        assert_eq!(
            dhcp.dns_server.clone().unwrap().dns_ip().len(),
            2,
            "DNS name nbr entries"
        );

        assert_eq!(
            dhcp.domain_name.unwrap().value(),
            "lallier.local",
            "Router IP"
        );

        println!(
            "DNS name ip: {:#x?}",
            dhcp.dns_server.clone().unwrap().dns_ip()
        );
    }

    #[test]
    fn dhcp_ack_to_request() {
        //--- File 1556.pcap ID:0x747172f6
        let packet: Vec<u8> = vec![
            0x2, 0x1, 0x6, 0x0, 0x74, 0x71, 0x72, 0xf6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xc0, 0xa8, 0x3, 0x82, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb8, 0x85, 0x84, 0x9a,
            0xf0, 0x17, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x63, 0x82, 0x53, 0x63, 0x35, 0x1, 0x5, 0x3a, 0x4, 0x0, 0x3, 0xf4, 0x80, 0x3b, 0x4,
            0x0, 0x6, 0xeb, 0xe0, 0x33, 0x4, 0x0, 0x7, 0xe9, 0x0, 0x36, 0x4, 0xc0, 0xa8, 0x3, 0xe6,
            0x1, 0x4, 0xff, 0xff, 0xff, 0x0, 0x51, 0x3, 0x3, 0xff, 0x0, 0x3, 0x4, 0xc0, 0xa8, 0x3,
            0x1, 0x6, 0x8, 0xc0, 0xa8, 0x3, 0xe6, 0xc0, 0xa8, 0x2, 0xe6, 0xf, 0xe, 0x6c, 0x61,
            0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x0, 0xff,
        ];

        print_hex(packet.clone());

        let mut dhcp = Dhcp::new(&packet);
        dhcp.get_options();

        assert_eq!(
            dhcp.msg_type.is_some(),
            true,
            "DHCP option message type is present"
        );

        assert_eq!(
            dhcp.msg_type.unwrap().request,
            5,
            "DHCP option message type"
        );

        assert_eq!(dhcp.server_id.is_some(), true, "Server ID is present");
        assert_eq!(dhcp.server_id.unwrap().value(), 0xc0a803e6, "Server ID");

        assert_eq!(dhcp.subnet_mask.is_some(), true, "Subnet mask is present");
        assert_eq!(dhcp.subnet_mask.unwrap().value(), 0xffffff00, "IP Mask");

        assert_eq!(dhcp.router.is_some(), true, "Router present");
        assert_eq!(dhcp.router.unwrap().value(), 0xc0a80301, "Router IP");

        assert_eq!(dhcp.dns_server.is_some(), true, "DNS name present");
        assert_eq!(
            dhcp.dns_server.clone().unwrap().dns_ip().len(),
            2,
            "DNS name nbr entries"
        );

        assert_eq!(
            dhcp.domain_name.unwrap().value(),
            "lallier.local",
            "Router IP"
        );

        assert_eq!(dhcp.renewal_time.is_some(), true, "Renewal time present");
        assert_eq!(
            dhcp.renewal_time.unwrap().value(),
            0x0003f480,
            "Renewal time"
        );

        assert_eq!(
            dhcp.rebinding_time.is_some(),
            true,
            "Rebinding time present"
        );
        assert_eq!(
            dhcp.rebinding_time.unwrap().value(),
            0x0006ebe0,
            "Rebinding time"
        );

        assert_eq!(
            dhcp.ip_addr_lease_time.is_some(),
            true,
            "IP address lease time"
        );
        assert_eq!(
            dhcp.ip_addr_lease_time.unwrap().value(),
            0x0007e900,
            "IP Lease time"
        );
        //----------------------------------------------------
        println!(
            "DNS name ip: {:#x?}",
            dhcp.dns_server.clone().unwrap().dns_ip()
        );
    }
}
