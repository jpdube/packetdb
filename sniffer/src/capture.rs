use database::config::CONFIG;
use database::dbconfig::DBConfig;
use pcap::{Capture, Device};
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufWriter, Write};
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;

// const BUFFER_SIZE: usize = 32;
const MAX_PACKETS_PER_FILE: u32 = 1_000;

const GLOBAL_HDR: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

#[derive(Default, Debug, Clone)]
struct PacketRef {
    file_id: u32,
    pkt_ptr: u32,
    packet: Vec<u8>,
    orig_len: u32,
    cap_len: u32,
    timestamp: u32,
    ts_us: u32,
}

pub fn capture(device_name: &str) -> Result<(), pcap::Error> {
    println!("Capture device: {}", device_name);
    let list: Vec<Device> = pcap::Device::list()?;
    let (tx_packet, rx_packet) = mpsc::channel();
    let (tx_db, rx_db) = mpsc::channel();
    // let channel_list: Vec<(tx_packet, rx_packet)> = Vec::new();

    //--- DB Thread

    // thread::spawn(move || {
    //     let mut display_counter: u16 = 0;

    //     for p in rx_db {
    //         display_counter += 1;
    //         // let pkt: DbInfo = p;
    //         // dbinfo_list.push(pkt);

    //         // if dbinfo_list.len() == 32 {
    //         //     let t_init = SystemTime::now();
    //         //     database.save_many(&dbinfo_list);
    //         //     dbinfo_list.clear();

    //         //     if display_counter > 100 {
    //         //         display_counter = 0;
    //         //         println!(
    //         //             "DB Execution time: {}us for 32 packets, {}us per packet",
    //         //             t_init.elapsed().unwrap().as_micros(),
    //         //             t_init.elapsed().unwrap().as_micros() / 32
    //         //         );
    //         //     }
    //         // }
    //     }
    // });

    thread::spawn(move || {
        let mut file_ptr: u32 = 0;
        let mut file_no: u32;
        let mut pkt_count: u32 = 0;
        // let header_only = false;
        let mut dbconfig: DBConfig = DBConfig::default();
        file_no = dbconfig.next_fileid();

        let mut bin_file =
            BufWriter::new(File::create(format!("{}/{}.pcap", &CONFIG.db_path, file_no)).unwrap());
        for p in rx_packet {
            if pkt_count >= MAX_PACKETS_PER_FILE {
                pkt_count = 0;
                file_no = dbconfig.next_fileid();
                bin_file = BufWriter::new(
                    File::create(format!("{}/{}.pcap", &CONFIG.db_path, file_no)).unwrap(),
                );
            }
            let t_init = SystemTime::now();

            let mut pkt: PacketRef = p;

            if file_ptr == 0 {
                bin_file.write_all(&GLOBAL_HDR).unwrap();
            }

            file_ptr = bin_file.stream_position().unwrap() as u32;
            pkt.file_id = file_no;
            pkt.pkt_ptr = file_ptr;

            tx_db.send(pkt.clone()).unwrap();

            bin_file.write_all(&pkt.packet).unwrap();

            println!(
                "PACKET: Execution time: {}us",
                t_init.elapsed().unwrap().as_micros()
            );
        }
    });

    // for dev in list {
    // println!("Device: {:?}", dev);
    // if dev.name == *device_name {
    println!("STarting capture on interface");
    let mut cap = Capture::from_device("en0")
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .open()
        .unwrap();

    println!("STarting packet capture");
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                println!("In loop packet capture");
                let pkt = PacketRef {
                    orig_len: packet.header.len,
                    cap_len: packet.header.caplen,
                    timestamp: packet.header.ts.tv_sec as u32,
                    ts_us: packet.header.ts.tv_usec as u32,
                    packet: packet.data.to_vec(),
                    file_id: 0,
                    pkt_ptr: 0,
                };
                let _ = tx_packet.send(pkt.clone()).unwrap();
            }
            Err(msg) => {
                println!("ERROR: {}", msg);
                return Err(msg);
            }
        }
    }
    // }
    // }
    // Ok(())
}
