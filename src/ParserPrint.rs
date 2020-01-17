use pktparse::arp::parse_arp_pkt;
use pktparse::ethernet::parse_ethernet_frame;
use pktparse::ethernet::EtherType;
use pktparse::ipv4::parse_ipv4_header;
use pktparse::ipv6::parse_ipv6_header;
use pktparse::ip::IPProtocol;
use pktparse::tcp::parse_tcp_header;
use pktparse::udp::parse_udp_header;
use dns_parser::Packet;
use tls_parser::tls::parse_tls_plaintext;
use tls_parser::tls::parse_tls_encrypted;

fn ParserPrint(data: &[u8]) {
    // parse Ethernet frame    
    let (dat, pe) = parse_ethernet_frame(data).unwrap();

    if pe.ethertype == EtherType::IPv4 {  //parse IPv4
        let (dat, pi) = parse_ipv4_header(dat).unwrap();

        if pi.protocol == IPProtocol::UDP {   //parse UDP
                let (dat, pu) = parse_udp_header(dat).unwrap();
                //parse del DNS
                if pu.dest_port == 53 {
                  let pd = Packet::parse(dat).unwrap();
                  println!(" {:?} .... {:?} .... {:?} .... {:?} \n", pe.ethertype, pi.protocol, pu.dest_port, pd.questions);
                } else {
                  println!(" {:?} .... {:?} .... {:?}  \n", pe.ethertype, pi.protocol, pu.dest_port); 
                }
        }else if pi.protocol == IPProtocol::TCP {  /////parse TCP
                  let (dat, ptcp) = parse_tcp_header(dat).unwrap();
                  
                  // pars del tls
                  if let Ok((dat, ptls)) = parse_tls_plaintext(dat){
                    println!(" {:?} .... {:?} .... {:?} .... {:?}\n", pe.ethertype, pi.protocol, ptcp.dest_port, ptls.msg);
                  } else if let Ok((dat, ptls)) = parse_tls_encrypted(dat){
                    println!(" {:?} .... {:?} .... {:?} .... {:?}\n", pe.ethertype, pi.protocol, ptcp.dest_port, ptls.hdr.version);
                  } else {
                    println!(" {:?} .... {:?} .... {:?} \n", pe.ethertype, pi.protocol, ptcp.dest_port);
                  }
                  
  
                
        } 
        
            
        
    
              
    } else if pe.ethertype == EtherType::ARP {  //parse ARP
        let (dat, pa) = parse_arp_pkt(dat).unwrap();
        println!(" {:?} .... {:?} \n", pe.ethertype, pa.operation);

    } else if pe.ethertype == EtherType::IPv6 {   //parse IPv6
        let (dat, pi) = parse_ipv6_header(dat).unwrap();
        println!(" {:?} .... {:?} \n", pe.ethertype, pi.next_header);
        if pi.next_header == IPProtocol::TCP {  //parse TCP
          let (dat, pt) = parse_tcp_header(dat).unwrap();
          println!(" {:?} .... {:?} .... {:?} \n", pe.ethertype, pi.next_header, pt.source_port);

        } else if pi.next_header == IPProtocol::UDP {  //parse UDP
            let (dat, pu) = parse_udp_header(dat).unwrap();
            //parse DNS
            if pu.dest_port == 53 {
              let pd = Packet::parse(dat).unwrap();
              println!(" {:?} .... {:?} .... {:?} .... {:?} \n", pe.ethertype, pi.next_header, pu.dest_port, pd.questions);
            } else {
                println!(" {:?} .... {:?} .... {:?}  \n", pe.ethertype, pi.next_header, pu.dest_port); 
            }
        }
      }
    
}
    
