use pktparse::ethernet::{EthernetFrame, parse_ethernet_frame, EtherType};
use pktparse::ipv4::{IPv4Header, parse_ipv4_header};
use pktparse::arp::{ArpPacket, parse_arp_pkt};
use pktparse::ipv6::{IPv6Header, parse_ipv6_header};
use pktparse::ip::IPProtocol;
use pktparse::tcp::{TcpHeader, parse_tcp_header};
use pktparse::udp::{UdpHeader, parse_udp_header};
use dns_parser::Packet;
use rtp_rs::*;
//use sipmsg::*;
use httparse::{/*Header,*/ parse_chunk_size/*, parse_headers*/};
//use snmp_parser::*;
//use snmpv3_parser::*;
use tls_parser::tls::{TlsPlaintext, parse_tls_plaintext};
use tls_parser::tls::{TlsEncrypted, parse_tls_encrypted};

pub struct Parser<'a>{
	data: &'a[u8],
}
#[derive(Debug)]
pub enum InternetLayer{
    IPv4(IPv4Header),
	IPv6(IPv6Header),
	None,
}
#[derive(Debug)]
pub enum TransportLayer {
  	UDP(UdpHeader),
  	TCP(TcpHeader),
	None,
}
#[derive(Debug)]
pub enum PresentationLayer<'a> {
    TLSE(TlsEncrypted<'a>),
	TLSP(TlsPlaintext<'a>),
	None,
}
#[derive(Debug)]
pub enum ApplicationLayer<'a> {
	HTTPheader(httparse::Status<(usize, &'a[httparse::Header<'a>])>),
  	HTTPchunck(httparse::Status<(usize, u64)>),
  	DNS(Packet<'a>),
  	//SIP(sipmsg::common::traits::NomParser::ParseResult),
	ARP(ArpPacket),
	RTP(RtpReader<'a>),
  	None,
}

pub struct ParsedPacket<'a>{
  	pub Networkacceslayer: EthernetFrame,
  	pub Internetlayer: InternetLayer,
  	pub Transportlayer: TransportLayer,
  	pub Presentationlayer: PresentationLayer<'a>,
  	pub Applicationlayer: ApplicationLayer<'a>, 
}
impl <'a> ParsedPacket<'a>{
  	pub fn new(networkacces: EthernetFrame, internet:  InternetLayer, transport:  TransportLayer, presentation: PresentationLayer<'a>, application:  ApplicationLayer<'a>) -> ParsedPacket<'a> {
    	ParsedPacket{
      		Networkacceslayer: networkacces,
      		Internetlayer: internet,
      		Transportlayer: transport,
      		Presentationlayer: presentation,
      		Applicationlayer: application, 
    	} 
  	}

 	pub fn dump(&self) {
    	println!("{:?} \n",self.Networkacceslayer);
      	println!("{:?} \n",self.Internetlayer);
      	println!("{:?} \n",self.Transportlayer);
      	println!("{:?} \n",self.Presentationlayer);
      	println!("{:?} \n\n\n\n\n",self.Applicationlayer);
  	}
}

impl <'a> Parser<'a> {
  	pub fn new(testo: &'a[u8]) -> Parser<'a>{
      	Parser{
       		data: testo,
      	}
 	}
	  
	pub fn parser_ethernet(&self, data: &'a[u8]) -> Result<ParsedPacket<'a>, String> {
      	// parse Ethernet frame    
      	match parse_ethernet_frame(data){
          	Ok((dat,networkacces)) => {
            	match networkacces.ethertype {
              		EtherType::IPv4 => {
                		let actualpacket = self.parser_ipv4(dat, networkacces);
                		actualpacket
            		}
            		EtherType::ARP => {
                		let actualpacket = self.parser_arp(dat, networkacces);
                		actualpacket
					}
					EtherType::IPv6 => {
                		let actualpacket = self.parser_ipv6(dat, networkacces);
                		actualpacket
              		}
              		_ => {
                  		let internet = InternetLayer::None;
                  		let transport = TransportLayer::None;
                  		let presentation = PresentationLayer::None;
                  		let application = ApplicationLayer::None;
                  		let actualpacket = ParsedPacket::new( networkacces, internet, transport, presentation, application);
                  		Ok(actualpacket)
              		}
          		}
          	}
          	Err(err) => Err("non è un pacchetto di rete".to_string()),
      	}
	}
	 
  	fn parser_ipv4(&self, data: &'a[u8], networkacces: EthernetFrame) -> Result<ParsedPacket<'a>, String> {
      	//parse IPv4 protocol
      	match parse_ipv4_header(data){
          	Ok((dat, internet)) => {
            	match internet.protocol {
              		IPProtocol::UDP => {
                		let actualpacket = self.parser_udp(dat, networkacces, InternetLayer::IPv4(internet));
                		actualpacket  
              		}
              		IPProtocol::TCP => {
                		let actualpacket = self.parser_tcp(dat, networkacces, InternetLayer::IPv4(internet));
                		actualpacket  
              		}
              		_ => {
                		let transport = TransportLayer::None;
                		let presentation = PresentationLayer::None;
                		let application = ApplicationLayer::None;
                		let actualpacket = ParsedPacket::new( networkacces, InternetLayer::IPv4(internet), transport, presentation, application);
                		Ok(actualpacket)
              		}
            	}
          	}
          	Err(err) => Err("non è un pacchetto IPv4".to_string()),
      	}
  	}
	
	fn parser_ipv6(&self, data: &'a[u8], networkacces: EthernetFrame) -> Result<ParsedPacket<'a>, String> {
		//parse IPv4 protocol
		match parse_ipv6_header(data){
			Ok((dat, internet)) => {
			  	match internet.next_header {
					IPProtocol::UDP => {
					  	let actualpacket = self.parser_udp(dat, networkacces, InternetLayer::IPv6(internet));
					  	actualpacket  
					}
					IPProtocol::TCP => {
					  	let actualpacket = self.parser_tcp(dat, networkacces, InternetLayer::IPv6(internet));
					  	actualpacket  
					}
					_ => {
					  	let transport = TransportLayer::None;
					  	let presentation = PresentationLayer::None;
					  	let application = ApplicationLayer::None;
					  	let actualpacket = ParsedPacket::new( networkacces, InternetLayer::IPv6(internet), transport, presentation, application);
					  	Ok(actualpacket)
					}
			  	}
			}
			Err(err) => Err("non è un pacchetto IPv6".to_string()),
		}
	}

	fn parser_tcp(&self, data: &'a[u8], networkacces: EthernetFrame, internet: InternetLayer) -> Result<ParsedPacket<'a>, String> {
    	//parse TCP header
    	match parse_tcp_header(data){
        	Ok((dat, transport)) => {
				match transport.dest_port{
                    80 => {
						let actualpacket = self.parser_tls(dat, networkacces, internet, transport);
						actualpacket
                    }
                    8080 => {
						let actualpacket = self.parser_tls(dat, networkacces, internet, transport);
						actualpacket
                    }
                    443 => {
						let actualpacket = self.parser_tls(dat, networkacces, internet, transport);
						actualpacket
                    }
                    _ => {
          				let application = ApplicationLayer::None;
          				let actualpacket = self.parser_tls_only(dat, networkacces, internet, transport, application);
						actualpacket
					}
                }
        	}
        	Err(err) => Err("TCP non riconosciuto".to_string()),
    	}
  	}

  	fn parser_udp(&self, data: &'a[u8], networkacces: EthernetFrame, internet: InternetLayer) -> Result<ParsedPacket<'a>, String> {
    	match parse_udp_header(data){
        	Ok((dat, transport)) => {
          		match transport.dest_port {
            		53 => {
                		let actualpacket = self.parser_dns(dat, networkacces, internet, transport);
                		actualpacket
            		}
            		5353 => {
                		let actualpacket = self.parser_dns(dat, networkacces, internet, transport);
                		actualpacket
            		}
            		/*5060 => {
              			let actualpacket = self.parser_sip(dat, networkacces, internet, transport);
              			actualpacket
            		}*/
            		_ => {
						match transport.source_port {
                    		53 => {
                        		let actualpacket = self.parser_dns(dat, networkacces, internet, transport);
                        		actualpacket
                    		}
                    		5353 => {
                        		let actualpacket = self.parser_dns(dat, networkacces, internet, transport);
                        		actualpacket
                    		}
                    		_ => {
								match RtpReader::new(dat){
									Ok(application) => {
										let presentation = PresentationLayer::None;
										let actualpacket = ParsedPacket::new( networkacces, internet, TransportLayer::UDP(transport), presentation, ApplicationLayer::RTP(application));
                      					Ok(actualpacket)
									}
									Err(err) => {
										let presentation = PresentationLayer::None;
										let application = ApplicationLayer::None;
										let actualpacket = ParsedPacket::new( networkacces, internet, TransportLayer::UDP(transport), presentation, application);
                      					Ok(actualpacket)
									}
								}
                    		}
                		}
          			}
				}
			}
        	Err(err) => Err("UDP non riconosciuto".to_string()),
    	}
	}

	fn parser_tls(&self, data: &'a[u8], networkacces: EthernetFrame, internet: InternetLayer, transport: TcpHeader) -> Result<ParsedPacket<'a>, String> {
        match parse_tls_plaintext(data){
            Ok((dat, presentation)) => {
				let actualpacket = self.parser_http(dat, networkacces, internet, transport, PresentationLayer::TLSP(presentation));
				actualpacket
			}
            Err(err) => {
                match parse_tls_encrypted(data){
                    Ok((dat, presentation)) => {
						let actualpacket = self.parser_http(dat, networkacces, internet, transport, PresentationLayer::TLSE(presentation));
						actualpacket
					}
                    Err(err) => {
						let presentation = PresentationLayer::None;
						let actualpacket = self.parser_http(data, networkacces, internet, transport, presentation);
						actualpacket
					}
                }
            }
        }
    }

	fn parser_tls_only(&self, data: &'a[u8], networkacces: EthernetFrame, internet: InternetLayer, transport: TcpHeader, application: ApplicationLayer<'a>) -> Result<ParsedPacket<'a>, String> {
        match parse_tls_plaintext(data){
            Ok((dat, presentation)) => {
				let actualpacket = ParsedPacket::new(networkacces, internet, TransportLayer::TCP(transport), PresentationLayer::TLSP(presentation), application);
          		Ok(actualpacket)
			}
            Err(err) => {
                match parse_tls_encrypted(data){
                    Ok((dat, presentation)) => {
						let actualpacket = ParsedPacket::new(networkacces, internet, TransportLayer::TCP(transport), PresentationLayer::TLSE(presentation), application);
          				Ok(actualpacket)
					}
                    Err(err) => {
						let presentation = PresentationLayer::None;
						let actualpacket = ParsedPacket::new(networkacces, internet, TransportLayer::TCP(transport), presentation, application);
          				Ok(actualpacket)
					}
                }
            }
        }
	}
	
	fn parser_http(&self, data: &'a[u8], networkacces: EthernetFrame, internet: InternetLayer, transport: TcpHeader, presentation: PresentationLayer<'a>) -> Result<ParsedPacket<'a>, String> {
        match parse_chunk_size(data){
            Ok(application) => {
				let actualpacket = ParsedPacket::new(networkacces, internet, TransportLayer::TCP(transport), presentation, ApplicationLayer::HTTPchunck(application));
          		Ok(actualpacket)
            }
            Err(err) => {
                /*let mut headers = [httparse::EMPTY_HEADER; 32];
                match parse_headers(data, &mut headers).unwrap(){
                    httparse::Status::Complete((size, headers)) => {
						let mut app = [httparse::EMPTY_HEADER; 32];
						let application = parse_headers(data, mut app).unwrap();
						let actualpacket = ParsedPacket::new(networkacces, internet, TransportLayer::TCP(transport), presentation, ApplicationLayer::HTTPheader(application));
          				Ok(actualpacket)
                    }
                    Error =>  Err("HTTP non riconosciuto".to_string()),
				}*/
				let application = ApplicationLayer::None;
				let actualpacket = ParsedPacket::new(networkacces, internet, TransportLayer::TCP(transport), presentation, application);
          		Ok(actualpacket)
            }
        }
    }

	fn parser_dns(&self, data: &'a[u8], networkacces: EthernetFrame, internet: InternetLayer, transport: UdpHeader) -> Result<ParsedPacket<'a>, String> {
    	//parse DNS level 7
    	match Packet::parse(data){
        	Ok(application) => {
          		let presentation = PresentationLayer::None;
          		let actualpacket = ParsedPacket::new(networkacces, internet, TransportLayer::UDP(transport), presentation, ApplicationLayer::DNS(application));
          		Ok(actualpacket)
        	}
        	Err(err) => {
				let presentation = PresentationLayer::None;
				let application = ApplicationLayer::None;
          		let actualpacket = ParsedPacket::new(networkacces, internet, TransportLayer::UDP(transport), presentation, application);
          		Ok(actualpacket)
			}
    	}
  	}

    /*	fn parser_sip(&self, data: &'a[u8], networkacces: EthernetFrame, internet: InternetLayer, transport: UdpHeader) -> Result<ParsedPacket<'a>, String> {
		//parse SIP level 7
		match sipmsg::common::traits::NomParser::parse(data){
			Ok((dat, application)) => {
				let presentation = PresentationLayer::None;
				let actualpacket = ParsedPacket::new(networkacces, internet, TransportLayer::UDP(transport), presentation, ApplicationLayer::SIP(application));
				Ok(actualpacket)
			}
			Err(err) => {
				let presentation = PresentationLayer::None;
				let application = ApplicationLayer::None;
				let actualpacket = ParsedPacket::new(networkacces, internet, TransportLayer::UDP(transport), presentation, application);
				Ok(actualpacket)
			}
		}  
	}*/

  	fn parser_arp(&self, data: &'a[u8], networkacces: EthernetFrame) -> Result<ParsedPacket<'a>, String> {
    	//parse ARP 
    	match parse_arp_pkt(data){
        	Ok((dat,application)) => {
          		let internet = InternetLayer::None;
          		let transport = TransportLayer::None;
          		let presentation = PresentationLayer::None;
          		let actualpacket = ParsedPacket::new(networkacces, internet, transport, presentation, ApplicationLayer::ARP(application));
          		Ok(actualpacket)
        	}
        	Err(err) => {
				let internet = InternetLayer::None;
          		let transport = TransportLayer::None;
				let presentation = PresentationLayer::None;
				let application = ApplicationLayer::None;
          		let actualpacket = ParsedPacket::new(networkacces, internet, transport, presentation, application);
          		Ok(actualpacket)
			}
    	}
  	}	

  	pub fn parse_packet(&self) -> Result<ParsedPacket<'a>, String> {
      	match self.parser_ethernet(self.data) {
          	Ok(frame) => {
              	let actualpacket = frame;
              	Ok(actualpacket)
          	}
          	Err(err) => {
              	Err("Non si può parsare questo pacchetto".to_string())
          	}
      	} 
  	}
 
}










