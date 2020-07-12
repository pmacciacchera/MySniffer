use dns_parser::Packet;
use pktparse::arp::{parse_arp_pkt, Operation};
use pktparse::ethernet::{parse_ethernet_frame, EtherType};
use pktparse::ip::IPProtocol;
use pktparse::ipv4::parse_ipv4_header;
use pktparse::ipv6::parse_ipv6_header;
use pktparse::tcp::{parse_tcp_header, TcpHeader, TcpOption};
use pktparse::udp::{parse_udp_header, UdpHeader};
use rtp_rs::*;
//use sipmsg::*;
use httparse::{parse_chunk_size, parse_headers};
use pktparse::ethernet::MacAddress;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use tls_parser::tls::{parse_tls_encrypted, parse_tls_plaintext};

#[derive(Debug, Serialize)]
pub enum Info {
    Ether(EtherType),
    IPv4(u8),
    IPv6(u8),
    UDP(u16),
    TCP(Option<Vec<TcpOption>>),
    TLS(String),
    HTTP(String),
    HTTPheader(String),
    DNSnameserver(String),
    DNS(String),
    RTP(u8),
    //SIP(Vec<SipHeader<'a>>),
    ARP(Operation),
}
#[derive(Debug, Serialize)]
pub enum Address {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    MAC(MacAddress),
    None,
}
#[derive(Debug, Serialize)]
pub struct ParsedPacket {
    pub source: Address,
    pub destination: Address,
    pub protocol: String,
    pub info: Info,
}
impl ParsedPacket {
    pub fn new(protocol: String, info: Info) -> ParsedPacket {
        ParsedPacket {
            source: Address::None,
            destination: Address::None,
            protocol: protocol,
            info: info,
        }
    }

    pub fn set_addr(&mut self, source_addr: Address, dest_addr: Address) {
        self.source = source_addr;
        self.destination = dest_addr;
    }
}

pub struct Parser<'a> {
    data: &'a [u8],
}

impl<'a> Parser<'a> {
    pub fn new(testo: &'a [u8]) -> Parser {
        Parser { data: testo }
    }

    pub fn parser_ethernet(&self, data: &'a [u8]) -> Result<ParsedPacket, String> {
        // parse Ethernet frame
        match parse_ethernet_frame(data) {
            Ok((dat, networkacces)) => match networkacces.ethertype {
                EtherType::IPv4 => {
                    let actualpacket = self.parser_ipv4(dat);
                    actualpacket
                }
                EtherType::ARP => {
                    let actualpacket = self.parser_arp(dat);
                    actualpacket
                }
                EtherType::IPv6 => {
                    let actualpacket = self.parser_ipv6(dat);
                    actualpacket
                }
                _ => {
                    let mut actualpacket = ParsedPacket::new(
                        "Ethernet".to_string(),
                        Info::Ether(networkacces.ethertype),
                    );
                    actualpacket.set_addr(
                        Address::MAC(networkacces.source_mac),
                        Address::MAC(networkacces.dest_mac),
                    );
                    Ok(actualpacket)
                }
            },
            Err(_err) => Err("non è un pacchetto di rete".to_string()),
        }
    }

    fn parser_ipv4(&self, data: &'a [u8]) -> Result<ParsedPacket, String> {
        //parse IPv4 protocol
        match parse_ipv4_header(data) {
            Ok((dat, internet)) => match internet.protocol {
                IPProtocol::UDP => {
                    let mut actualpacket = self.parser_udp(dat).unwrap();
                    actualpacket.set_addr(
                        Address::IPv4(internet.source_addr),
                        Address::IPv4(internet.dest_addr),
                    );
                    Ok(actualpacket)
                }
                IPProtocol::TCP => {
                    let mut actualpacket = self.parser_tcp(dat).unwrap();
                    actualpacket.set_addr(
                        Address::IPv4(internet.source_addr),
                        Address::IPv4(internet.dest_addr),
                    );
                    Ok(actualpacket)
                }
                _ => {
                    let mut actualpacket =
                        ParsedPacket::new("IPv4".to_string(), Info::IPv4(internet.version));
                    actualpacket.set_addr(
                        Address::IPv4(internet.source_addr),
                        Address::IPv4(internet.dest_addr),
                    );
                    Ok(actualpacket)
                }
            },
            Err(_err) => Err("non è un pacchetto IPv4".to_string()),
        }
    }

    fn parser_ipv6(&self, data: &'a [u8]) -> Result<ParsedPacket, String> {
        //parse IPv6 protocol
        match parse_ipv6_header(data) {
            Ok((dat, internet)) => match internet.next_header {
                IPProtocol::UDP => {
                    let mut actualpacket = self.parser_udp(dat).unwrap();
                    actualpacket.set_addr(
                        Address::IPv6(internet.source_addr),
                        Address::IPv6(internet.dest_addr),
                    );
                    Ok(actualpacket)
                }
                IPProtocol::TCP => {
                    let mut actualpacket = self.parser_tcp(dat).unwrap();
                    actualpacket.set_addr(
                        Address::IPv6(internet.source_addr),
                        Address::IPv6(internet.dest_addr),
                    );
                    Ok(actualpacket)
                }
                _ => {
                    let mut actualpacket =
                        ParsedPacket::new("IPv6".to_string(), Info::IPv6(internet.version));
                    actualpacket.set_addr(
                        Address::IPv6(internet.source_addr),
                        Address::IPv6(internet.dest_addr),
                    );
                    Ok(actualpacket)
                }
            },
            Err(_err) => Err("non è un pacchetto IPv6".to_string()),
        }
    }

    fn parser_tcp(&self, data: &'a [u8]) -> Result<ParsedPacket, String> {
        //parse TCP header
        match parse_tcp_header(data) {
            Ok((dat, transport)) => match transport.dest_port {
                80 => {
                    let actualpacket = self.parser_http(dat, transport);
                    actualpacket
                }
                8080 => {
                    let actualpacket = self.parser_http(dat, transport);
                    actualpacket
                }
                443 => {
                    let actualpacket = self.parser_http(dat, transport);
                    actualpacket
                }
                _ => {
                    let actualpacket = self.parser_tls(dat, transport);
                    actualpacket
                }
            },
            Err(_err) => Err("TCP non riconosciuto".to_string()),
        }
    }

    fn parser_udp(&self, data: &'a [u8]) -> Result<ParsedPacket, String> {
        match parse_udp_header(data) {
            Ok((dat, transport)) => {
                match transport.dest_port {
                    53 | 5353 => {
                        let actualpacket = self.parser_dns(dat, transport);
                        actualpacket
                    }
                    /*5060 => {
                          let actualpacket = self.parser_sip(dat, transport);
                          actualpacket
                    }*/
                    _ => match transport.source_port {
                        53 | 5353 => {
                            let actualpacket = self.parser_dns(dat, transport);
                            actualpacket
                        }
                        _ => match RtpReader::new(dat) {
                            Ok(application) => {
                                let actualpacket = ParsedPacket::new(
                                    "RTP".to_string(),
                                    Info::RTP(application.version()),
                                );
                                Ok(actualpacket)
                            }
                            Err(_err) => {
                                let actualpacket = ParsedPacket::new(
                                    "UDP".to_string(),
                                    Info::UDP(transport.checksum),
                                );
                                Ok(actualpacket)
                            }
                        },
                    },
                }
            }
            Err(_err) => Err("UDP non riconosciuto".to_string()),
        }
    }

    fn parser_tls(&self, data: &'a [u8], transport: TcpHeader) -> Result<ParsedPacket, String> {
        match parse_tls_plaintext(data) {
            Ok((_dat, presentation)) => {
                let actualpacket = ParsedPacket::new(
                    "TLS".to_string(),
                    Info::TLS(presentation.hdr.record_type.to_string()),
                );
                Ok(actualpacket)
            }
            Err(_err) => match parse_tls_encrypted(data) {
                Ok((_dat, presentation)) => {
                    let actualpacket = ParsedPacket::new(
                        "TLS".to_string(),
                        Info::TLS(presentation.hdr.record_type.to_string()),
                    );
                    Ok(actualpacket)
                }
                Err(_err) => {
                    let actualpacket =
                        ParsedPacket::new("TCP".to_string(), Info::TCP(transport.options));
                    Ok(actualpacket)
                }
            },
        }
    }

    fn parser_http(&self, data: &'a [u8], transport: TcpHeader) -> Result<ParsedPacket, String> {
        match parse_chunk_size(data) {
            Ok(application) => match application.is_complete() {
                true => {
                    let actualpacket =
                        ParsedPacket::new("HTTP".to_string(), Info::HTTP("Complete".to_string()));
                    Ok(actualpacket)
                }
                false => {
                    let actualpacket =
                        ParsedPacket::new("HTTP".to_string(), Info::HTTP("Partial".to_string()));
                    Ok(actualpacket)
                }
            },
            Err(_err) => {
                let mut headers = [httparse::EMPTY_HEADER; 500];
                match parse_headers(data, &mut headers) {
                    Ok(stato) => match stato.is_complete() {
                        true => {
                            let actualpacket = ParsedPacket::new(
                                "HTTP".to_string(),
                                Info::HTTPheader("Complete".to_string()),
                            );
                            Ok(actualpacket)
                        }
                        false => {
                            let actualpacket = ParsedPacket::new(
                                "HTTP".to_string(),
                                Info::HTTPheader("Partial".to_string()),
                            );
                            Ok(actualpacket)
                        }
                    },
                    Err(_err) => {
                        let actualpacket =
                            ParsedPacket::new("TCP".to_string(), Info::TCP(transport.options));
                        Ok(actualpacket)
                    }
                }
            }
        }
    }

    fn parser_dns(&self, data: &'a [u8], transport: UdpHeader) -> Result<ParsedPacket, String> {
        //parse DNS level 7
        match Packet::parse(data) {
            Ok(application) => {
                if application.header.questions != 0 {
                    let actualpacket = ParsedPacket::new(
                        "DNS".to_string(),
                        Info::DNS(application.questions.first().unwrap().qname.to_string()),
                    );
                    Ok(actualpacket)
                } else {
                    let actualpacket = ParsedPacket::new(
                        "DNS".to_string(),
                        Info::DNSnameserver(
                            application.nameservers.first().unwrap().name.to_string(),
                        ),
                    );
                    Ok(actualpacket)
                }
            }
            Err(_err) => {
                let actualpacket =
                    ParsedPacket::new("UDP".to_string(), Info::UDP(transport.checksum));
                Ok(actualpacket)
            }
        }
    }

    /*  fn parser_sip(&self, data: &'a[u8], transport: UdpHeader) -> Result<ParsedPacket<'a>, String> {
        //parse SIP level 7
        match parse_sip_headers(data){
            Ok((_dat, application)) => {
                let actualpacket = ParsedPacket::new( "SIP".to_string(), Info::SIP(application));
                Ok(actualpacket)
            }
            Err(_err) => {
                let actualpacket = ParsedPacket::new( "UDP".to_string(), Info::UDP(transport.checksum));
                Ok(actualpacket)
            }
        }
    }*/

    fn parser_arp(&self, data: &'a [u8]) -> Result<ParsedPacket, String> {
        //parse ARP
        match parse_arp_pkt(data) {
            Ok((_dat, application)) => {
                let mut actualpacket =
                    ParsedPacket::new("ARP".to_string(), Info::ARP(application.operation));
                actualpacket.set_addr(
                    Address::IPv4(application.src_addr),
                    Address::IPv4(application.dest_addr),
                );
                Ok(actualpacket)
            }
            Err(_err) => {
                let actualpacket = ParsedPacket::new("Ether".to_string(), Info::IPv4(99));
                Ok(actualpacket)
            }
        }
    }

    pub fn parse_packet(&self) -> Result<ParsedPacket, String> {
        match self.parser_ethernet(self.data) {
            Ok(frame) => {
                let actualpacket = frame;
                Ok(actualpacket)
            }
            Err(_err) => Err("Non si può parsare questo pacchetto".to_string()),
        }
    }
}
