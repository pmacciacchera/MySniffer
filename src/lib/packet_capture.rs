extern crate pcap;
use pcap::{Device, Capture, Active};

pub struct  InitializeCapture {
    promisc_parameter: bool,
    timeout_parameter: i32,
    buffer_size_parameter: i32,
    snaplen_parameter: i32,
}

impl InitializeCapture  {
    pub fn new() -> InitializeCapture {
        InitializeCapture {
            promisc_parameter : false,
            timeout_parameter : 0,
            buffer_size_parameter : 1000000,
            snaplen_parameter: 65535,
        }
    }

    pub fn set_promisc (&mut self, value: bool) -> &mut InitializeCapture {
        self.promisc_parameter=value;
        self
    }

    pub fn set_timeout(&mut self, value :i32) -> &mut InitializeCapture {
        self.timeout_parameter = value;
        self
    }

    pub fn set_buffer_size (&mut self, value : i32) -> &mut InitializeCapture {
        self.buffer_size_parameter=value;
        self
    }

    pub fn set_snaplen (&mut self, value : i32) -> &mut InitializeCapture {
        self.snaplen_parameter= value;
        self
    }

    pub fn finalize(&self) -> StartCapture {
        StartCapture {
            promisc_parameter: self.promisc_parameter,
            timeout_parameter: self.timeout_parameter,
            buffer_size_parameter: self.buffer_size_parameter,
            snaplen_parameter: self.snaplen_parameter
        }
    }
}

pub struct StartCapture  {
    promisc_parameter: bool,
    timeout_parameter: i32,
    buffer_size_parameter: i32,
    snaplen_parameter: i32,
}

impl StartCapture {
    pub fn get_promisc_parameter(&self) -> bool {
        self.promisc_parameter
    }

    pub fn get_timout_parameter(&self) -> i32 {
        self.timeout_parameter
    }

    pub fn get_buffer_size_parameter(&self) -> i32 {
        self.buffer_size_parameter
    }

    pub fn get_snaplen(&self) -> i32 {
        self.snaplen_parameter
    }

    fn active_capture(initialized_capture: StartCapture, device: Device) -> Capture<Active> {
        let mut start_capture = Capture::from_device(device).unwrap()
            .promisc(initialized_capture.promisc_parameter)
            .snaplen(initialized_capture.snaplen_parameter)
            .timeout(initialized_capture.timeout_parameter)
            .buffer_size(initialized_capture.buffer_size_parameter)
            .open().unwrap();
        return start_capture
    }

    pub fn streaming_capture(mut initialized_capture: StartCapture, device: Device) {
        let mut start_capture = StartCapture::active_capture(initialized_capture, device);
        while let Ok(packet) = start_capture.next() {
            println!("{:?}",packet);
        }
    }

    pub fn capture_to_file(mut initialized_capture: StartCapture, device: Device, filename: &str) {
        let mut start_capture = StartCapture::active_capture(initialized_capture, device);
        let mut stream_file = Capture::savefile(&start_capture, filename)
            .unwrap();
        while let Ok(packet) = start_capture.next() {
            stream_file.write(&packet);
        }
    }

    pub fn capture_from_file(mut initialized_capture: StartCapture, filename: &str) {
        let mut start_capture = Capture::from_file(filename).unwrap();
        while let Ok(packet) = start_capture.next() {}
    }

}

pub fn device_list() -> Vec<String> {
    let devices: Vec<String> = Device::list().unwrap().iter().map(|val| val.name.clone()).collect();
    println!("Available interfaces : ");
    devices.iter().for_each(|val| println!("* {}", val));
    return devices
}

pub fn get_default_device() -> Device {
    let main_device = Device::lookup().unwrap();
    return main_device
}

