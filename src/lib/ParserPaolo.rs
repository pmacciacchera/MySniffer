use pktparse::arp::parse_arp_pkt;
use pktparse::ethernet::parse_ethernet_frame;
use pktparse::ethernet::EtherType;
use pktparse::ipv4::parse_ipv4_header;
use pktparse::ipv6::parse_ipv6_header;
use pktparse::ip::IPProtocol;
use pktparse::tcp::parse_tcp_header;
use pktparse::udp::parse_udp_header;
use dns_parser::Packet;
use rtp_rs::*;
use sipmsg::header::parse_headers;
//use tls_parser::tls::parse_tls_plaintext;
//use tls_parser::tls::parse_tls_encrypted;

pub fn ParserPaolo(data: &[u8]) {
    // parse Ethernet frame    
    let (dat, pe) = parse_ethernet_frame(data).unwrap();

    //Parse Ethernet frame
    match pe.ethertype {
        EtherType::IPv4 => {
          let (dat, pi4) = parse_ipv4_header(dat).unwrap();
          match pi4.protocol {
            IPProtocol::TCP => {
              let (dat, pt4) = parse_tcp_header(dat).unwrap();
              //match let Ok((dat, ptls)) {
                //parse_tls_plaintext(dat) => println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?} Tls message: {:?}\n", pe.ethertype, pi4.protocol, pt4.dest_port, ptls.msg),
                //parse_tls_encrypted(dat) => println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?} Version: {:?}\n", pe.ethertype, pi4.protocol, pt4.dest_port, ptls.hdr.version),
                //_ => println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?}  \n", pe.ethertype, pi4.protocol, pt4.dest_port),
              //}
            }
            IPProtocol::UDP => {
              let (dat, pu4) = parse_udp_header(dat).unwrap();
              match pu4.dest_port {
                53 => {
                  let pd = Packet::parse(dat).unwrap();
                  println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?} Question: {:?} \n", pe.ethertype, pi4.protocol, pu4.dest_port, pd.questions);
                }
                5353 => {
                  let pd = Packet::parse(dat).unwrap();
                  println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?} Question: {:?} \n", pe.ethertype, pi4.protocol, pu4.dest_port, pd.questions);
                }
                5060 => {
                  let ps = parse_headers(dat).unwrap();
                  println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?} sip: {:?} \n", pe.ethertype, pi4.protocol, pu4.dest_port, ps);

                }
                _ => match pu4.source_port {
                        53 => {
                          let pd = Packet::parse(dat).unwrap();
                          println!("EtherType: {:?} Protocol: {:?} Source Port: {:?} Question: {:?} \n", pe.ethertype, pi4.protocol, pu4.source_port, pd.questions);
                        }
                        5353 => {
                          let pd = Packet::parse(dat).unwrap();
                          println!("EtherType: {:?} Protocol: {:?} Source Port: {:?} Question: {:?} \n", pe.ethertype, pi4.protocol, pu4.source_port, pd.questions);
                        }
                        _ =>println!("EtherType: {:?} Protocol: {:?} Source Port: {:?} Destination Port: {:?}  \n", pe.ethertype, pi4.protocol, pu4.source_port,pu4.dest_port),
                      }
              }
              if let Ok(rtp) = RtpReader::new(data) {
                println!("Sequence number {:?}", rtp.sequence_number());
                println!("Payload length {:?}", rtp.payload().len());
                println!("Payload type {:?}\n", rtp.payload_type());
            }
            }
            _ => println!("Header del {:?} non riconosciuto \n", pi4.protocol),
          }
        }
        EtherType::ARP => {
          let (dat, pa) = parse_arp_pkt(dat).unwrap();
          println!("EtherType: {:?} Operation: {:?} \n", pe.ethertype, pa.operation);
        }
        EtherType::IPv6 => {
          let (dat, pi6) = parse_ipv6_header(dat).unwrap();
          match pi6.next_header {
            IPProtocol::TCP => {
              let (dat, pt6) = parse_tcp_header(dat).unwrap();
            }
            IPProtocol::UDP => {
              let (dat, pu6) = parse_udp_header(dat).unwrap();
            }
            _ => println!("Header del {:?} non riconosciuto \n", pi6.next_header),
          }
        }
        _ => println!("EtherType {:?} non parsato \n", pe.ethertype),
    }
    





















    //check protocollo IPv6
    //match pi6.next_header {
        //IPProtocol::TCP => let (dat, pt6) = parse_tcp_header(dat).unwrap(),
        //IPProtocol::UDP => let (dat, pu6) = parse_udp_header(dat).unwrap(),
        //_ => println!("Header del {:?} non riconosciuto \n", pi6.next_header),
    //}
    //check protocollo IPv4
    //match pi4.protocol {
      //IPProtocol::TCP => let (dat, pt4) = parse_tcp_header(dat).unwrap(),
      //IPProtocol::UDP => let (dat, pu4) = parse_udp_header(dat).unwrap(),
      //_ => println!("Header del {:?} non riconosciuto \n", pi4.protocol),
    //}
    //terminale UDP con DNS per IPv4
    //match pu4.dest_port {
        //53 => {
          //let pd = Packet::parse(dat).unwrap();
          //println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?} Queation: {:?} \n", pe.ethertype, pi4.protocol, pu4.dest_port, pd.questions);
        //}
        //_ => println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?}  \n", pe.ethertype, pi4.protocol, pu4.dest_port),
    //}
    //terminale TCP con TLS per IPv4
    //match let Ok((dat, ptls)) {
      //parse_tls_plaintext(dat) => println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?} Tls message: {:?}\n", pe.ethertype, pi4.protocol, pt4.dest_port, ptls.msg),
      //parse_tls_encrypted(dat) => println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?} Version: {:?}\n", pe.ethertype, pi4.protocol, pt4.dest_port, ptls.hdr.version),
      //_ => println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?}  \n", pe.ethertype, pi4.protocol, pt4.dest_port),
    //}
}