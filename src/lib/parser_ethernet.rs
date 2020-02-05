use pktparse::ethernet::{EthernetFrame, parse_ethernet_frame, EtherType};
use pktparse::ipv4::{IPv4Header, parse_ipv4_header};
use pktparse::arp::parse_arp_pkt;
//use pktparse::ipv6::parse_ipv6_header;
use pktparse::ip::IPProtocol;
use pktparse::tcp::parse_tcp_header;
use pktparse::udp::{UdpHeader, parse_udp_header};
use dns_parser::Packet;
use rtp_rs::*;
use sipmsg::header;
//use snmp_parser::*;
//use snmpv3_parser::*;
use tls_parser::tls::{parse_tls_plaintext, parse_tls_encrypted};
use httparse::*;


pub fn parser_ethernet(data: &[u8]) {
    // parse Ethernet frame    
  let (dat, pe) = parse_ethernet_frame(data).unwrap();

  //match Ethernet frame
  match pe.ethertype {
      EtherType::IPv4 => parser_ipv4(dat, pe),        
      EtherType::ARP => parser_arp(dat, pe),
      //EtherType::IPv6 => parser_ipv6(dat, pe),
      _ => println!("EtherType {:?} non parsato \n", pe.ethertype),
  }
    
}
fn parser_ipv4(data: &[u8], pe: EthernetFrame) {
  //parse IPv4 protocol
  let (dat, pi) = parse_ipv4_header(data).unwrap();

  //match IPv4 protocol
  match pi.protocol {
      IPProtocol::TCP => parser_tcp(dat, pe, pi),
      IPProtocol::UDP => parser_udp(dat, pe, pi),
      _ => println!("Header del {:?} non riconosciuto \n", pi.protocol),
  }
}
fn parser_arp(data: &[u8], pe: EthernetFrame) {
  //parse ARP 
  let (_dat, pa) = parse_arp_pkt(data).unwrap();
  println!("EtherType: {:?} Operation: {:?} \n", pe.ethertype, pa.operation);
}
/*fn parser_ipv6(data: &[u8], pe: EthernetFrame) {
  //parse IPv6 protocol
  let (dat, pi6) = parse_ipv6_header(data).unwrap();
  
  //match IPv6 protocol
  match pi6.next_header {
    IPProtocol::TCP => parser_TCP( dat, pe, pi6),
    IPProtocol::UDP => parser_UDP(dat, pe, pi6),
    _ => println!("Header del {:?} non riconosciuto \n", pi6.next_header),
          
  }
}*/
fn parser_tcp(data: &[u8], pe: EthernetFrame, pi:IPv4Header) {
  //parse TCP header
  let (dat, pt) = parse_tcp_header(data).unwrap();
  if let Ok((dat, ptls)) = parse_tls_plaintext(dat) {
    println!("TLS plaintext riuscito\n  {:?}\n", ptls);
  }else if let Ok((dat, ptls)) = parse_tls_encrypted(dat){
    println!("TLS encrypted riuscito\n {:?}\n", ptls);
    
  }else {
    println!("TLS non riuscito  \n");
  }

  match pt.dest_port {
      80 => parser_http(dat),
      8080 => parser_http(dat),
      443 => parser_http(dat),
      _ => println!("no porta http\n"),
  }

}

fn parser_udp(data: &[u8], pe: EthernetFrame, pi:IPv4Header) {
  let (dat, pt) = parse_udp_header(data).unwrap();
  match pt.dest_port {
      53 => parser_dns(dat, pe, pi, pt),
      5353 => parser_dns(dat, pe, pi, pt),
      5060 => parser_sip(dat, pe, pi, pt),
      _ => match pt.source_port {
              53 => parser_dns(dat, pe, pi, pt),
              5353 => parser_dns(dat, pe, pi, pt),
              _ =>println!("EtherType: {:?} Protocol: {:?} Source Port: {:?} Destination Port: {:?}  \n", pe.ethertype, pi.protocol, pt.source_port, pt.dest_port),
      }
  }
  
  if let Ok(rtp) = RtpReader::new(data) {
      //level 7
        println!("Sequence number {:?}", rtp.sequence_number());
        println!("Payload length {:?}", rtp.payload().len());
        println!("Payload type {:?}\n", rtp.payload_type());
  }
}
fn parser_dns(data: &[u8], pe: EthernetFrame, pi:IPv4Header, pt: UdpHeader) {
  //parse DNS level 7
  let pa = Packet::parse(data).unwrap();
  println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?} Question: {:?} \n", pe.ethertype, pi.protocol, pt.dest_port, pa.questions);
}
fn parser_sip(data: &[u8], pe: EthernetFrame, pi:IPv4Header, pt: UdpHeader) {
  //parse SIP level 7
  let pa = header::parse_headers(data).unwrap();
  println!("EtherType: {:?} Protocol: {:?} Destination Port: {:?} SIP: {:?} \n", pe.ethertype, pi.protocol, pt.dest_port, pa);

}


fn parser_http(data: &[u8]) {
    if let Ok(status) = parse_chunk_size(data){
        println!("Status: {:?} \n", status);
        if status.is_complete(){
            println!("Status: {:?} \n", status.unwrap());
        }
    } else {
        let mut headers = [httparse::EMPTY_HEADER; 500];
        if let Ok(status) = parse_headers(data, &mut headers) {
            println!("HTTP header: {:?} \n", status);
            if status.is_complete(){
                println!("Status: {:?} \n", status.unwrap());
            }
        }else {
            println!("non funziona http \n");
        }
    }
}









