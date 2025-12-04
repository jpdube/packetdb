use crate::schema::Schema;
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use field::field_type::get_type_len;
use field::pfield::Field;
use field::serialize_field::SerializeField;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
// use std::time::Instant;

const MAGIC_NO: u32 = 0x10023004;
const VERSION: u16 = 1;

#[derive(Clone)]
pub struct IndexMeta {
    magic_no: u32,
    version: u16,
    field: Schema,
    name: String,
    ptr_list: Vec<(Field, u32)>,
    filename: String,
}

impl IndexMeta {
    pub fn new(name: &str, field: Schema) -> Self {
        Self {
            magic_no: MAGIC_NO,
            version: VERSION,
            field: field.clone(),
            name: name.to_string(),
            ptr_list: Vec::new(),
            filename: format!("{}_{}.meta", name, field.name),
        }
    }

    pub fn read(&mut self) -> Result<()> {
        println!("Opening {} of Field len {}", self.name, self.field.type_len);

        if Path::new(&self.filename).exists() {
            let mut reader = BufReader::new(File::open(&self.filename)?);

            self.magic_no = reader.read_u32::<BigEndian>()?;

            self.version = reader.read_u16::<BigEndian>()?;

            let ftype: u16 = reader.read_u16::<BigEndian>()?;

            let fname_len: u16 = reader.read_u16::<BigEndian>()?;

            let mut buffer: Vec<u8> = vec![0; fname_len as usize];
            reader.read_exact(&mut buffer)?;
            let fname = str::from_utf8(&buffer)?;

            let schema = Schema::new(ftype, fname);

            if self.is_valid() {
                let mut buffer_field: Vec<u8> = Vec::new();
                buffer_field.resize(get_type_len(schema.ftype) as usize, 0);

                let mut ptr: u32;

                while reader.read_exact(&mut buffer_field).is_ok() {
                    ptr = reader.read_u32::<BigEndian>()?;

                    let field = Field::from_binary_to_field(ftype, fname, buffer_field.to_vec());

                    eprintln!("Reading meta index: {}:{:x}", field, ptr);
                    self.ptr_list.push((field, ptr));
                }
            }
        }

        Ok(())
    }

    fn is_valid(&self) -> bool {
        self.magic_no == MAGIC_NO && self.version == VERSION
    }

    pub fn append(&mut self, field: Field, ptr: u32) -> Result<()> {
        // eprintln!("Received: {field}:{ptr}");
        self.ptr_list.push((field, ptr));
        Ok(())
    }

    pub fn clear(&mut self) {
        self.ptr_list.clear();
    }

    pub fn save(&mut self) -> Result<()> {
        let mut writer: BufWriter<File>;

        if Path::new(&self.filename).exists() {
            eprintln!("In append mode: {}", self.filename);
            writer = BufWriter::new(fs::OpenOptions::new().append(true).open(&self.filename)?);
        } else {
            writer = BufWriter::new(File::create(&self.filename)?);
            writer.write_u32::<BigEndian>(self.magic_no)?;
            writer.write_u16::<BigEndian>(self.version)?;
            writer.write_all(&self.field.into_bytes()?)?;
        };

        for f in &self.ptr_list {
            writer.write_all(&f.0.field_to_binary())?;
            writer.write_u32::<BigEndian>(f.1)?;
        }

        Ok(())
    }
}
