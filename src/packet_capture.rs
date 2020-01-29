extern crate pcap;

use pcap::{Device, Capture};
use std::fs::OpenOptions;
use std::io::Write;
use std::fs::File;



pub fn device_list (){
    let devices: Vec<String> = Device::list().unwrap().iter().map(|val| val.name.clone()).collect();
    println!("Available interfaces : ");
    devices.iter().for_each(|val| println!("* {}", val));
}


pub fn write_packet_to_file(file_name: &str) {
    let main_device = Device::lookup().unwrap();
    let mut cap = Capture::from_device(main_device)
        .unwrap()
        .open()
        .unwrap();
    let mut stream_file = Capture::savefile(&cap,file_name)
        .unwrap();
    while let Ok(packet) = cap.next() {
        stream_file.write(&packet);
    }
}

