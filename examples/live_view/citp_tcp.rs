use std::io::{self, BufRead, Read, Write};
use std::{io::BufReader, net::TcpStream};

use citp::protocol as citp;

use citp::{
    Header,
    ReadFromBytes,
    WriteToBytes,
};

use crate::CITP_HEADER_LEN;


#[derive(Debug)]
pub struct CitpNet {
    read_buf: Box<[u8]>,
    write_buf: Vec<u8>,

    reader: BufReader<TcpStream>,
    writer: TcpStream,
}
impl CitpNet {
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        Ok(Self {
            read_buf: vec![0u8; 64 * 1024].into_boxed_slice(),
            write_buf: Vec::with_capacity(4096),
            reader: BufReader::new(stream.try_clone()?),
            writer: stream,
        })
    }

    pub fn write_packet<T: WriteToBytes>(&mut self, message: T) -> io::Result<()> {
        self.write_buf.clear();
        message.write_to_bytes(&mut self.write_buf).unwrap(); // SAFE: write into vector
        self.writer.write_all(&self.write_buf)?;
        self.writer.flush()?;
        Ok(())
    }

    fn mem_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.len() > haystack.len() {
            return None;
        }

        let mut offset = 0;
        while offset < (haystack.len() - needle.len())  {
            if haystack[offset..].starts_with(needle) {
                return Some(offset);
            }
            offset+=1;
        }
        None
    }

    /// Receive a packet, will block until one is received
    pub fn receive_packet(&mut self) -> io::Result<Option<(Header, &[u8])>> {
        let cookie_buf = self.reader.fill_buf()?;
        let cookie = if cookie_buf.len() < 4 {
            // come on, no way we're actually reading fewer than 4 bytes
            if b"CITP".starts_with(cookie_buf) {
                *b"CITP"
            } else {
                *b"AAAA"
            }
        } else {
            [cookie_buf[0], cookie_buf[1], cookie_buf[2], cookie_buf[3]]
        };
        if cookie != *b"CITP" {
            println!("ERROR with CITP cookie");
            match Self::mem_find(cookie_buf, b"CITP") {
                Some(l) => {
                    println!("Found start of packet at index {l}, skipping data before that");
                    self.reader.consume(l);
                },
                None => {
                    println!("Failed to find start of packet, dropping all data");
                    let l = cookie_buf.len();
                    self.reader.consume(l);
                },
            }
            return Ok(None);
        }
    
        self.reader.read_exact(&mut self.read_buf[..CITP_HEADER_LEN])?;
        let header = citp::Header::read_from_bytes(&self.read_buf[..CITP_HEADER_LEN])?;
        self.reader.read_exact(&mut self.read_buf[CITP_HEADER_LEN..header.message_size as usize])?;
        let body = &self.read_buf[CITP_HEADER_LEN..header.message_size as usize];

        Ok(Some((header, body)))
    }
}
