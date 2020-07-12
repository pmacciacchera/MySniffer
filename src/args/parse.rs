use clap::{App, Arg, ArgMatches, SubCommand};
pub struct ParseSubcommand {}
use crate::lib::packet_capture::*;

impl<'a, 'b> ParseSubcommand {
    pub fn new() -> ParseSubcommand {
        ParseSubcommand {}
    }

    pub fn get_subcommand(&self) -> App<'a, 'b> {
        let parse_args = vec![
            Arg::with_name("file_name").required(true),
            Arg::with_name("number")
                .help("Choose the number of the packet to show more information.")
                .takes_value(true)
                .long("number")
                .short("n"),
            Arg::with_name("protocol")
                .help("Choose the protocol of the packets.")
                .takes_value(true)
                .long("protocolo")
                .short("p"),
        ];

        SubCommand::with_name("parse")
            .about("Parse pcap files.")
            .args(&parse_args)
    }

    pub fn start(&self, args: &ArgMatches) {
        let number;
        
        if let Some(val) = args.value_of("number") {
            number = val.parse().unwrap();
            if number == 0 {
                if let Some(name) = args.value_of("file_name") {
                    parse_file(name);
                }
            } else {
                if let Some(name) = args.value_of("file_name") {
                    capture_from_file(name, number);
                }
            }
        } else {
            if let Some(val) = args.value_of("protocol") {
                let protocol = val;
                if let Some(name) = args.value_of("file_name") {
                    choose_protocol(name, protocol);
                }
            } else {
                if let Some(name) = args.value_of("file_name") {
                    parse_file(name);
                }
            }
        }
    }
}
