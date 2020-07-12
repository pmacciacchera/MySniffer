mod capture;
mod parse;

use clap::{crate_authors, crate_description, crate_name, crate_version, App};
use crate::args::capture::CaptureSubcommand;
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
            let capture_device = capture_subcommand.set_args(run_args);
            let device;

            if let Some(handle) = run_args.value_of("device") {
                //cambio device;
                device = handle;
            } else {
                device = "get_default_device";
            }

            let start = capture_device.finalize();
            if let Some(file) = run_args.value_of("savefile") {
                capture_to_file(start, device, file);
            } else {
                streaming_capture(start, device);
            }
        }
    }

    if let Some(args) = matches.subcommand_matches("parse") {
        parse_subcommand.start(args);
    }
}
