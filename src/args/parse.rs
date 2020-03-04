use clap::{App, Arg, ArgMatches, SubCommand};
pub struct ParseSubcommand {}

impl<'a, 'b> ParseSubcommand {
    pub fn new() -> ParseSubcommand {
        ParseSubcommand {}
    }

    pub fn get_subcommand(&self) -> App<'a, 'b> {
        let parse_args = vec![
            Arg::with_name("file_name").required(true),
            Arg::with_name("savefile")
                .help("Save parsed packets.")
                .takes_value(true)
                .short("s")
                .long("savefile"),
            /*Arg::with_name("filter")
                .help("Set filter to the capture using the given BPF program string.")
                .takes_value(true)
                .long("filter")
                .short("f"),*/
            Arg::with_name("deep")
                .help("Show more information about a parsed packet.")
                .takes_value(true)
                .long("deep")
                .short("d")
        ];

        SubCommand::with_name("parse")
            .about("Parse pcap files.")
            .args(&parse_args)
    }

    pub fn start(&self, args: &ArgMatches) {
        let mut save_file_path = None;
        //let mut packet_capture = PacketCapture::new();
        //let mut filter = None;

        /*if let Some(val) = args.value_of("filter") {
            filter = Some(val.to_string());
        }*/
        if let Some(val) = args.value_of("savefile") {
            save_file_path = Some(val);
        }
        /*if let Some(val) = args.value_of("file_name") {
            packet_capture.parse_from_file(val, save_file_path, filter);
        }*/
    }



}