use crate::index_meta::IndexMeta;
use crate::record::Record;
use crate::schema::Schema;
use anyhow::{Result, bail};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use field::field_type::get_type_len;
use field::pfield::Field;
use field::serialize_field::SerializeField;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
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

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Index header: MagicNo: {}, Version: {}, Options: {}",
            self.magic_no, self.version, self.options
        )
    }
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
    meta: IndexMeta,
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
            fieldname: fieldname.clone(),
            key_list: HashMap::new(),
            write_ptr: 0,
            header: Header::new(),
            meta: IndexMeta::new(filename, fieldname.clone()),
        }
    }

    pub fn append(&mut self, row: Record, ptr: u32) {
        if let Some(field) = row.get(&self.fieldname.name) {
            if let Some(key) = self.key_list.get_mut(&field) {
                key.push(ptr);
            } else {
                self.key_list.insert(field, vec![ptr]);
            }

            self.write_ptr += 1;
        }

        if self.write_ptr >= 1024 {
            self.save().unwrap();
        }
    }

    pub fn save(&mut self) -> Result<()> {
        let mut writer: BufWriter<File>;

        if Path::new(&self.filename).exists() {
            writer = BufWriter::new(fs::OpenOptions::new().append(true).open(&self.filename)?);
            writer.seek(std::io::SeekFrom::End(0))?;
        } else {
            writer = BufWriter::new(File::create(&self.filename)?);

            // Write the header of the index
            writer.write_all(&self.header.to_binary()?)?;

            writer.write_all(&self.fieldname.into_bytes()?)?;
        }

        // Write the index to disk
        let mut buffer: Vec<u8> = Vec::new();
        let mut value_buffer: Vec<u8> = Vec::new();

        let file_pos = writer.stream_position()? as u32;

        self.meta.clear();

        for (key, values) in self.key_list.iter() {
            value_buffer.write_all(&key.field_to_binary())?;

            for v in values {
                value_buffer.write_u32::<BigEndian>(*v)?;
            }

            self.meta
                .append(key.clone(), file_pos + (buffer.len() as u32))?;

            buffer.write_u32::<BigEndian>(value_buffer.len() as u32)?;
            buffer.write_all(&value_buffer)?;

            value_buffer.clear();
        }

        writer.write_all(&buffer)?;

        self.key_list.clear();
        self.write_ptr = 0;
        self.meta.save()?;

        Ok(())
    }

    pub fn read(&mut self) -> Result<()> {
        self.key_list.clear();

        let mut reader = BufReader::new(File::open(&self.filename)?);

        let mut buffer: Vec<u8> = vec![0; 8];

        // Read the header
        reader.read_exact(&mut buffer)?;
        self.header = Header::from_binary(&buffer);

        if !self.header.is_valid() {
            bail!("Invalid index header: {}", self.header);
        }

        let start = Instant::now();

        //--- Read the field defintion
        let ftype: u16 = reader.read_u16::<BigEndian>()?;

        let fname_len: u16 = reader.read_u16::<BigEndian>()?;

        buffer.resize(fname_len as usize, 0);
        reader.read_exact(&mut buffer)?;
        let bin_fname = buffer.clone();
        let fname = str::from_utf8(&bin_fname)?;

        while let Ok(index_block_len) = reader.read_u32::<BigEndian>() {
            buffer.resize(index_block_len as usize, 0);
            reader.read_exact(&mut buffer)?;

            let field = Field::from_binary_to_field(
                ftype,
                fname,
                buffer[0..get_type_len(ftype) as usize].to_vec(),
            );

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

        let end = start.elapsed();
        println!("Index read speed time: {}us", end.as_micros());

        self.meta.read()?;

        Ok(())
    }
}
