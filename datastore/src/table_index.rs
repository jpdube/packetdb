use crate::row::Row;
use crate::schema::Schema;
use anyhow::Result;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use field::field_type::get_type_len;
use field::pfield::Field;
use field::serialize_field::SerializeField;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::time::Instant;

//                      Index file structure
// +------------------------------+--------------+---------------+
// |           Magic no           |   Version    |    Options    |
// |             u32              |     u16      |      u16      |
// |                              |              |               |
// +---------------+--------------+--------------+---------------+
// |  Field type   |   FieldLen   |          Fieldname           |
// |      u16      |     u16      |             [u8]             |
// |               |              |                              |
// +---------------+--------------+------------------------------+
// |        Index (1) size        |        Index (1) data        |
// |             u32              |             [u8]             |
// |                              |                              |
// +------------------------------+------------------------------+
// |        Index (n) size        |        Index (n) data        |
// |             u32              |             [u8]             |
// |                              |                              |
// +------------------------------+------------------------------+

const MAGIC_NO: u32 = 0x1a2b3c4d;
const VERSION: u16 = 1;

#[derive(Clone)]
struct Header {
    magic_no: u32,
    version: u16,
    options: u16,
}

impl Header {
    pub fn new() -> Self {
        Self {
            magic_no: MAGIC_NO,
            version: VERSION,
            options: 0,
        }
    }

    pub fn to_binary(&self) -> Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(8);

        result.write_u32::<BigEndian>(self.magic_no)?;
        result.write_u16::<BigEndian>(self.version)?;
        result.write_u16::<BigEndian>(self.options)?;

        Ok(result)
    }

    pub fn from_binary(raw_bytes: &[u8]) -> Self {
        Self {
            magic_no: BigEndian::read_u32(&raw_bytes[0..4]),
            version: BigEndian::read_u16(&raw_bytes[4..6]),
            options: BigEndian::read_u16(&raw_bytes[6..8]),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic_no == MAGIC_NO && self.version == VERSION
    }
}

#[derive(Clone)]
pub struct TableIndex {
    filename: String,
    fieldname: Schema,
    key_list: HashMap<Field, Vec<u32>>,
    write_ptr: usize,
    header: Header,
}

impl fmt::Display for TableIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Filename: {}, Fieldname: {}",
            self.filename, self.fieldname
        )
    }
}

impl TableIndex {
    pub fn new(filename: &str, fieldname: Schema) -> Self {
        Self {
            filename: format!("{}_{}.idx", filename, fieldname.name),
            fieldname,
            key_list: HashMap::new(),
            write_ptr: 0,
            header: Header::new(),
        }
    }

    pub fn append(&mut self, row: Row, ptr: u32) {
        if let Some(field) = row.get_field(&self.fieldname.name) {
            if let Some(key) = self.key_list.get_mut(&field) {
                key.push(ptr);
            } else {
                self.key_list.insert(field, vec![ptr]);
            }

            self.write_ptr += 1;
        }

        if self.write_ptr >= 1024 {
            // println!("---> Dumping block: {}", self.write_ptr);
            self.save().unwrap();
        }
    }

    pub fn save(&mut self) -> Result<()> {
        // println!(
        //     "Saving index for: {}, Nbr items to flush: {}",
        //     self.fieldname, self.write_ptr
        // );

        let mut writer: BufWriter<File>;

        if Path::new(&self.filename).exists() {
            writer = BufWriter::new(fs::OpenOptions::new().append(true).open(&self.filename)?);
        } else {
            writer = BufWriter::new(File::create(&self.filename)?);

            // Write the header of the index
            writer.write_all(&self.header.to_binary()?)?;

            writer.write_all(&self.fieldname.into_bytes()?)?;
        }

        // Write the index to disk
        let mut buffer: Vec<u8> = Vec::new();
        let mut value_buffer: Vec<u8> = Vec::new();
        for (key, values) in self.key_list.iter() {
            // println!("INDEX Key: {key}, Value: {:?}", values);

            value_buffer.write_all(&key.field_to_binary())?;

            for v in values {
                value_buffer.write_u32::<BigEndian>(*v)?;
            }

            buffer.write_u32::<BigEndian>(value_buffer.len() as u32)?;
            buffer.write_all(&value_buffer)?;

            value_buffer.clear();
        }
        writer.write_all(&buffer)?;

        self.key_list.clear();
        self.write_ptr = 0;

        Ok(())
    }

    pub fn read(&mut self) -> Result<()> {
        let start = Instant::now();
        let mut reader = BufReader::new(File::open(&self.filename)?);

        let mut buffer: Vec<u8> = vec![0; 8];

        // Read the header
        reader.read_exact(&mut buffer)?;
        self.header = Header::from_binary(&buffer);

        if self.header.is_valid() {
            //--- Read the field defintion
            buffer.resize(2, 0);
            reader.read_exact(&mut buffer)?;
            let ftype = BigEndian::read_u16(&buffer);

            reader.read_exact(&mut buffer)?;
            let fname_len = BigEndian::read_u16(&buffer);

            buffer.resize(fname_len as usize, 0);
            reader.read_exact(&mut buffer)?;
            let bin_fname = buffer.clone();
            let fname = str::from_utf8(&bin_fname)?;

            let mut buffer_u32: Vec<u8> = vec![0; 4];

            let mut index_block_len: u32;
            while reader.read_exact(&mut buffer_u32).is_ok() {
                index_block_len = BigEndian::read_u32(&buffer_u32);
                buffer.resize(index_block_len as usize, 0);
                reader.read_exact(&mut buffer)?;

                // println!("==== FNAME LEN: {fname}");
                let field = Field::from_binary_to_field(
                    ftype,
                    fname,
                    buffer[0..get_type_len(ftype) as usize].to_vec(),
                );

                // println!("****> Index field value: {}", _field);
                let mut ptr: u32;
                for byte_ptr in buffer[get_type_len(ftype) as usize..].chunks(4) {
                    ptr = BigEndian::read_u32(byte_ptr);
                    if let Some(key) = self.key_list.get_mut(&field.clone()) {
                        key.push(ptr);
                    } else {
                        self.key_list.insert(field.clone(), vec![ptr]);
                    }
                }
            }
        }

        let end = start.elapsed();

        // println!("Index list: {:x?}", &self.key_list);

        println!("Index read speed time: {}us", end.as_micros());

        Ok(())
    }
}
