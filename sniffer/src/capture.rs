use crate::packet_ref::PacketRef;
use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};
use database::dbconfig::DBConfig;
use database::index_manager::IndexManager;
use dblib::config::CONFIG;
use pcap::Capture;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::mpsc;
use std::thread;

const MAX_PACKETS_PER_FILE: u32 = 50_000;

const GLOBAL_HDR: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
];

pub fn capture(device_name: &str) -> Result<()> {
    println!("Capture device: {}", device_name);
    let (tx_packet, rx_packet) = mpsc::channel();
    let (tx_db, rx_db) = mpsc::channel();

    thread::spawn(move || {
        let index_mgr: IndexManager = IndexManager::default();
        for file_id in rx_db {
            index_mgr.index_one_file(file_id);
        }
    });

    thread::spawn(move || {
        let mut file_no: u32;
        let mut pkt_count: u32 = 0;
        let mut dbconfig: DBConfig = DBConfig::default();
        let mut header: Vec<u8> = Vec::with_capacity(16);

        file_no = dbconfig.next_fileid().unwrap();
        let mut bin_file =
            BufWriter::new(File::create(format!("{}/{}.pcap", &CONFIG.db_path, file_no)).unwrap());
        bin_file.write_all(&GLOBAL_HDR).unwrap();

        for p in rx_packet {
            if pkt_count >= MAX_PACKETS_PER_FILE {
                tx_db.send(file_no).unwrap();

                pkt_count = 0;
                file_no = dbconfig.next_fileid().unwrap();
                bin_file = BufWriter::new(
                    File::create(format!("{}/{}.pcap", &CONFIG.db_path, file_no)).unwrap(),
                );
                bin_file.write_all(&GLOBAL_HDR).unwrap();
            }

            let pkt: PacketRef = p;
            pkt_count += 1;

            header.clear();
            header.write_u32::<LittleEndian>(pkt.timestamp).unwrap();
            header.write_u32::<LittleEndian>(pkt.ts_us).unwrap();
            header.write_u32::<LittleEndian>(pkt.cap_len).unwrap();
            header.write_u32::<LittleEndian>(pkt.orig_len).unwrap();

            bin_file.write_all(&header).unwrap();
            bin_file.write_all(&pkt.packet).unwrap();
        }
    });

    println!("Starting capture on interface: {}", device_name);
    let mut cap = Capture::from_device(device_name)
        .unwrap()
        .promisc(true)
        .open()
        .unwrap();

    println!("Starting packet capture");
    while let Ok(packet) = cap.next_packet() {
        let pkt = PacketRef {
            orig_len: packet.header.len,
            cap_len: packet.header.caplen,
            timestamp: packet.header.ts.tv_sec as u32,
            ts_us: packet.header.ts.tv_usec as u32,
            packet: packet.data.to_vec(),
        };

        let _ = tx_packet.send(pkt)?;
    }

    Ok(())
}
