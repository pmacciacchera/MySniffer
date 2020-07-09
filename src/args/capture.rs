use clap::{App, Arg, ArgMatches, SubCommand};
use pcap::{Capture, Inactive};
use std::cell::RefCell;
use crate::lib::packet_capture::*;



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
            Arg::with_name("timeout")
                .help("Set the read timeout for the Capture. By default, this is 0, so it will block indefinitely.")
                .takes_value(true)
                .short("t")
                .long("timeout")
                .validator(is_i32),
            Arg::with_name("promisc")
                .help("Set promiscuous mode on or off. By default, this is off.")
                .short("p")
                .long("promisc"),
            Arg::with_name("buffer_size")
                .help("Set the buffer size for incoming packet data. The default is 1000000. This should always be larger than the snaplen.")
                .takes_value(true)
                .short("b")
                .long("buffer_size")
                .validator(is_i32),
            Arg::with_name("snaplen")
                .help("Set the snaplen size (the maximum length of a packet captured into the buffer). \
                    Useful if you only want certain headers, but not the entire packet.The default is 65535.")
                .takes_value(true)
                .short("s")
                .long("snaplen")
                .validator(is_i32),
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

    pub fn set_args(&self, args: &ArgMatches) -> CaptureBuilder {
        
        let mut builder = CaptureBuilder::new();
        
        if let Some(val) = args.value_of("timeout") {
            
            builder.set_timeout(val.parse().unwrap());
        }
        if let Some(val) = args.value_of("promisc") {
            builder.set_promisc(val.parse().unwrap());
        }
        if let Some(val) = args.value_of("buffer_size") {
            builder.set_buffer_size(val.parse().unwrap());
        }
        if let Some(val) = args.value_of("snaplen") {
            builder.set_snaplen(val.parse().unwrap());
        }
        return builder;
    }
        
}