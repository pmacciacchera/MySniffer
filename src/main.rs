mod lib;

use pcap::Device;
use crate::lib::ParserPaolo::ParserPaolo;
use rtsparse::*;
    
fn main() {
<<<<<<< HEAD
  let mut cap = Device::lookup().unwrap().open().unwrap();
  while let Ok(packet) = cap.next() {
       ParserPaolo(packet.data);
  }
  
           
}
=======
}
>>>>>>> 152c21017a1006dcf03110597f50fb1236e8822f
