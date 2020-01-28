extern crate pcap;

use pcap::{Device, Capture};
use std::fs::OpenOptions;
use std::io::Write;
use std::fs::File;



pub fn write_packet_to_file(file_name: &str) {
    let mut stream_file = File::create(file_name).unwrap();
    stream_file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(file_name)
        .unwrap();
    let main_device = Device::lookup().unwrap();
    let mut cap = Capture::from_device(main_device)
        .unwrap()
        .open()
        .unwrap();
    while let Ok(packet) = cap.next() {
        stream_file.write_all(&packet)
            .unwrap();
    }
}