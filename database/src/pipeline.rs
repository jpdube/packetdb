use rayon::prelude::*;
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

// pub fn pipeline_test() {
//     let (tx_db, rx_db) = channel();
//     let (tx_db2, rx_db2) = channel();
//     let (tx_result, rx_result) = channel();

//     // thread::spawn(move || {
//     //     for p in rx_db2 {
//     //         tx_result.send(p);
//     //     }
//     // });

//     for i in 0..10 {
//         if i % 2 == 0 {
//             tx_db.send(i).unwrap();
//         } else {
//             tx_db2.send(i).unwrap();
//         }
//     }

//     for p in rx_result {
//         println!("Received: {}", p);
//     }
// }

static NTHREADS: i32 = 30;

pub fn pipeline_test2() {
    let mut pkt_list: Vec<i32> = Vec::new();
    let mut counter = 0;
    let mut processed_pkt: Vec<i32> = Vec::new();

    for i in 0..10 {
        pkt_list.push(i);
    }

    for pkt in pkt_list.chunks(10) {
        println!("Chunck: {:?}", pkt);

        let result: Vec<i32> = pkt.into_par_iter().map(|pkt| *pkt).collect();

        for p in result {
            if processed_pkt.len() < 32 {
                processed_pkt.push(p);
                counter += 1;
            }
        }
    }

    println!("Result: {:?}, Len: {}", processed_pkt, processed_pkt.len());
}

pub fn pipeline_test() {
    // Channels have two endpoints: the `Sender<T>` and the `Receiver<T>`,
    // where `T` is the type of the message to be transferred
    // (type annotation is superfluous)
    let (tx, rx): (Sender<String>, Receiver<String>) = channel();
    let (in_tx, in_rx): (Sender<String>, Receiver<String>) = channel();
    let mut children = Vec::new();

    let sender = in_tx.clone();
    for msg in 0..NTHREADS {
        sender.send(format!("Send: {msg}")).unwrap();
    }

    for id in 0..NTHREADS {
        // The sender endpoint can be copied
        let thread_tx = tx.clone();
        let msg = in_rx.recv().unwrap();

        // Each thread will send its id via the channel
        let child = thread::spawn(move || {
            // The thread takes ownership over `thread_tx`
            // Each thread queues a message in the channel
            thread_tx.send(format!("Received msg: [{}]", msg)).unwrap();

            // Sending is a non-blocking operation, the thread will continue
            // immediately after sending its message
            println!("thread {} finished", id);
        });

        children.push(child);
    }

    // Here, all the messages are collected
    let mut ids = Vec::with_capacity(NTHREADS as usize);
    for _ in 0..NTHREADS {
        // The `recv` method picks a message from the channel
        // `recv` will block the current thread if there are no messages available
        ids.push(rx.recv());
    }

    // Wait for the threads to complete any remaining work
    for child in children {
        child.join().expect("oops! the child thread panicked");
    }

    // Show the order in which the messages were sent
    println!("{:?}", ids);
}
