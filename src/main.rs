mod lib;

use pcap::Device;
use crate::lib::parser_ethernet::parser_ethernet;

    
fn main() {
  let mut cap = Device::lookup().unwrap().open().unwrap();
  while let Ok(packet) = cap.next() {
       parser_ethernet(packet.data);
  }
  
           
}