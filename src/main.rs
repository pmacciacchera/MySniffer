mod lib;

use pcap::Device;
use crate::lib::ParserPaolo::ParserPaolo;
use rtsparse::*;
    
fn main() {
  let mut cap = Device::lookup().unwrap().open().unwrap();
  while let Ok(packet) = cap.next() {
       ParserPaolo(packet.data);
  }
  
           
}