mod capture;
mod parse;

use clap::{crate_authors, crate_description, crate_name, crate_version, App};
use pcap::{Capture, Device};

use crate::args::capture::{CaptureSubcommand};
use crate::args::parse::ParseSubcommand;
use crate::lib::packet_capture::*;



pub fn parse_arguments() {
    let capture_subcommand = CaptureSubcommand::new();
    let parse_subcommand = ParseSubcommand::new();

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .subcommand(capture_subcommand.get_subcommand())
        .subcommand(parse_subcommand.get_subcommand())
        .get_matches();

    

    
    if let Some(sub) = matches.subcommand_matches("capture") {
        if sub.subcommand_matches("list").is_some() {
            device_list();
        } else if let Some(run_args) = sub.subcommand_matches("run") {
            let CaptureDevice = capture_subcommand.set_args(run_args);
            let device;
            
            if let Some(handle) = run_args.value_of("device") {
                //cambio device;
                device = get_default_device();
            } else {
                device = get_default_device();
            }

            let Start = CaptureDevice.finalize();
            if let Some(file) = run_args.value_of("savefile") {
                capture_to_file(Start,device,file);
            } else {
                streaming_capture(Start, device);
            }
            
        }
    }

    if let Some(args) = matches.subcommand_matches("parse") {
        parse_subcommand.start(args);
    }
}
