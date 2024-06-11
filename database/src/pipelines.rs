use std::sync::mpsc;
use std::thread;

pub fn pipeline_test() {
    let (tx_db, rx_db) = mpsc::channel();
    let channel_list: Vec<(tx_packet, recv_packet)> = Vec::new();

    thread::spawn(move || {
        let mut display_counter: u16 = 0;

        for p in rx_db {
            display_counter += 1;
            let pkt: DbInfo = p;
        }
    });
}
