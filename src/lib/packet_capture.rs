extern crate pcap;

use crate::lib::deep_parser::Parser;
use crate::lib::light_parser::{Parser as lightParser};
use pcap::{Active, Capture, Device};


pub struct CaptureBuilder {
    promisc_parameter: bool,
    timeout_parameter: i32,
    buffer_size_parameter: i32,
    snaplen_parameter: i32,
}

impl CaptureBuilder {
    // new() initialize a new Capture with default parameters
    pub fn new() -> CaptureBuilder {
        CaptureBuilder {
            promisc_parameter: false,
            timeout_parameter: 0,
            buffer_size_parameter: 1000000,
            snaplen_parameter: 65535,
        }
    }
    pub fn set_promisc(&mut self, value: bool) -> &mut CaptureBuilder {
        self.promisc_parameter = value;
        self
    }

    pub fn set_timeout(&mut self, value: i32) -> &mut CaptureBuilder {
        self.timeout_parameter = value;
        self
    }

    pub fn set_buffer_size(&mut self, value: i32) -> &mut CaptureBuilder {
        self.buffer_size_parameter = value;
        self
    }

    pub fn set_snaplen(&mut self, value: i32) -> &mut CaptureBuilder {
        self.snaplen_parameter = value;
        self
    }
    // finalize() create the StartCapture useful to start the packet capture with parameters
    pub fn finalize(&self) -> StartCapture {
        StartCapture {
            promisc_parameter: self.promisc_parameter,
            timeout_parameter: self.timeout_parameter,
            buffer_size_parameter: self.buffer_size_parameter,
            snaplen_parameter: self.snaplen_parameter,
        }
    }
}

pub struct StartCapture {
    promisc_parameter: bool,
    timeout_parameter: i32,
    buffer_size_parameter: i32,
    snaplen_parameter: i32,
}

impl StartCapture {
    pub fn get_promisc_parameter(&self) -> bool {
        self.promisc_parameter
    }

    pub fn get_timeout_parameter(&self) -> i32 {
        self.timeout_parameter
    }

    pub fn get_buffer_size_parameter(&self) -> i32 {
        self.buffer_size_parameter
    }

    pub fn get_snaplen_parameter(&self) -> i32 {
        self.snaplen_parameter
    }

    fn active_capture(initialized_capture: StartCapture, device: &str) -> Capture<Active> {
        let start_capture;
        if device != "get_default_device" {
            start_capture = Capture::from_device(device)
                .unwrap()
                .promisc(initialized_capture.get_promisc_parameter())
                .snaplen(initialized_capture.get_snaplen_parameter())
                .timeout(initialized_capture.get_timeout_parameter())
                .buffer_size(initialized_capture.get_buffer_size_parameter())
                .open()
                .unwrap();
        } else {
            let dev = get_default_device();
            start_capture = Capture::from_device(dev)
                .unwrap()
                .promisc(initialized_capture.get_promisc_parameter())
                .snaplen(initialized_capture.get_snaplen_parameter())
                .timeout(initialized_capture.get_timeout_parameter())
                .buffer_size(initialized_capture.get_buffer_size_parameter())
                .open()
                .unwrap();
        }
        return start_capture;
    }
}

// capture live in streaming without saving packet to file
pub fn streaming_capture(initialized_capture: StartCapture, device: &str) {
    println!("{:?} \n", device);
    let mut start_capture = StartCapture::active_capture(initialized_capture, device);
    let mut k = 1;
    print_coloums();
    while let Ok(packet) = start_capture.next() {
        let parser = lightParser::new(packet.data);
        let parsed_packet = parser.parse_packet().unwrap();
        println!(
            "{} | {:?} | {:?} | {:#?} | {:?} | {:?} |",
            k,
            parsed_packet.source,
            parsed_packet.source,
            packet.header.ts.tv_sec,
            parsed_packet.protocol,
            parsed_packet.info
        );
        k = k + 1;
    }
}

pub fn capture_to_file(initialized_capture: StartCapture, device: &str, filename: &str) {
    println!("{:?} \n", device);
    let mut start_capture = StartCapture::active_capture(initialized_capture, device);
    let mut stream_file = Capture::savefile(&start_capture, filename).unwrap();
    let mut k = 1;
    print_coloums();
    while let Ok(packet) = start_capture.next() {
        stream_file.write(&packet);
        let parser = lightParser::new(packet.data);
        let parsed_packet = parser.parse_packet().unwrap();
        println!(
            "{} | {:?} | {:?} | {:#?} | {:?} | {:?} |",
            k,
            parsed_packet.source,
            parsed_packet.source,
            packet.header.ts.tv_sec,
            parsed_packet.protocol,
            parsed_packet.info
        );
        k = k + 1;
    }
}

pub fn capture_from_file(filename: &str, numero: i32) {
    let mut c = 1;
    let mut start_capture = Capture::from_file(filename).unwrap();
    while let Ok(packet) = start_capture.next() {
        if c == numero {
            let parser = Parser::new(packet.data);
            let parsed_packet = parser.parse_packet().unwrap();
            parsed_packet.dump();
        }
        c = c + 1;
    }
}

pub fn parse_file(filename: &str) {
    print_coloums();
    let mut c = 1;
    let mut start_capture = Capture::from_file(filename).unwrap();
    while let Ok(packet) = start_capture.next() {
        let parser = lightParser::new(packet.data);
        let parsed_packet = parser.parse_packet().unwrap();
        println!(
            "{} | {:?} | {:?} | {:#?} | {:?} | {:?} |",
            c,
            parsed_packet.source,
            parsed_packet.source,
            packet.header.ts.tv_sec,
            parsed_packet.protocol,
            parsed_packet.info
        );
        c = c + 1;
    }
}

pub fn choose_protocol(filename: &str, protocol: &str) {
    print_coloums();
    let mut c = 1;
    let mut start_capture = Capture::from_file(filename).unwrap();
    while let Ok(packet) = start_capture.next() {
        let parser = lightParser::new(packet.data);
        let parsed_packet = parser.parse_packet().unwrap();
        if parsed_packet.protocol == protocol {
            println!(
                "{} | {:?} | {:?} | {:#?} | {:?} | {:?} |",
                c,
                parsed_packet.source,
                parsed_packet.source,
                packet.header.ts.tv_sec,
                parsed_packet.protocol,
                parsed_packet.info
            );
        }
        c = c + 1;
    }
}

pub fn device_list() -> Vec<String> {
    let devices: Vec<String> = Device::list()
        .unwrap()
        .iter()
        .map(|val| val.name.clone())
        .collect();
    println!("Available interfaces : ");
    devices.iter().for_each(|val| println!("* {}", val));
    return devices;
}

pub fn get_default_device() -> Device {
    let main_device = Device::lookup().unwrap();
    return main_device;
}

fn print_coloums() {
    println!(
        "{0: <5} | {1: <15} | {2: <15} | {3: <25} | {4: <15} | {5: <25} |",
        "Number", "Source IP", "Dest IP", "Timestamp", "Protocol", "Info"
    );
    println!("{:-^1$}", "-", 165,);
}
