use crate::lib::packet_capture;
use clap::{App, Arg, ArgMatches, SubCommand};
use pcap::{Capture, Inactive};
use std::cell::RefCell;



fn is_i32(val: String) -> Result<(), String> {
    match val.parse::<i32>() {
        Ok(_) => Ok(()),
        Err(err) => Err(err.to_string()),
    }
}


pub struct CaptureSubcommand {}

impl<'a, 'b> CaptureSubcommand {
    pub fn new() -> CaptureSubcommand {
        CaptureSubcommand {}
    }

    pub fn get_subcommand(&self) -> App<'a, 'b> {
        let run_args = vec![
            Arg::with_name("device")
                .help("Specify the device interface")
                .takes_value(true)
                .long("device")
                .short("d"),
            /*Arg::with_name("timeout")
                .help("Set the read timeout for the Capture. By default, this is 0, so it will block indefinitely.")
                .takes_value(true)
                .short("t")
                .long("timeout")
                .validator(is_i32),*/
            /*Arg::with_name("filter")
                .help("Set filter to the capture using the given BPF program string.")
                .takes_value(true)
                .long("filter")
                .short("f"),*/
            Arg::with_name("savefile")
                .help("Save the captured packets to file.")
                .takes_value(true)
                .long("savefile")
        ];

        SubCommand::with_name("capture")
            .about("Capture packets from interfaces.")
            .subcommand(SubCommand::with_name("list").about("List all interfaces."))
            .subcommand(
                SubCommand::with_name("run")
                    .about("Start capturing packets.")
                    .args(&run_args),
            )
    }

    /*pub fn run_args(
        &self,
        device: RefCell<Capture<Inactive>>,
        args: &ArgMatches,
    ) -> RefCell<Capture<Inactive>> {
        let mut device = device.into_inner();
        // the validators will ensure we are passing the proper type, hence using unwrap is not a problem.
        if let Some(val) = args.value_of("timeout") {
            device = device.timeout(val.parse().unwrap());
        }
        RefCell::new(device)
    }*/
    /*
    pub fn start(&self, device: RefCell<Capture<Inactive>>, args: &ArgMatches) {
        let device = device.into_inner();

        match device.open() {
            Ok(mut cap_handle) => {
                // Set pacp capture filters
                /*if let Some(val) = args.value_of("filter") {
                    cap_handle
                        .filter(val)
                        .expect("Filters invalid, please check the documentation.");
                }*/

                // To select between saving to file and printing to console.
                if let Some(val) = args.value_of("savefile") {
                    write_packet_to_file(val);
                } else {
                    print_to_console(cap_handle);
                }
            }
            Err(err) => {
                eprintln!("{:?}", err);
            }
        }
    }*/


    
}