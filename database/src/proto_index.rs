struct ProtoHeader {
    magic_no: u32,
    version: u16,
    options: u16,
    count: u32,
}

pub struct ProtoIndex {
    header: ProtoHeader,
    ptr_list: Vec<u8>,
    proto_id: u32,
    file_id: u32,
}

impl ProtoIndex {
    pub fn new() -> Self {
        Self {
            header: ProtoHeader {
                magic_no: 0,
                version: 0,
                options: 0,
                count: 0,
            },
            file_id: 0,
            proto_id: 0,
            ptr_list: Vec::new(),
        }
    }

    pub fn create_index(&mut self, ptr_list: &Vec<u32>) {
        let filename = format!("{}_{}.pidx", self.file_id, self.proto_id);
    }
}
