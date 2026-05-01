use std::{ffi::CString, fs, io, net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket}};

use socket2::{Domain, Protocol, Socket, Type};

use citp::protocol as citp;
use citp::{
    ReadFromBytes, SizeBytes,
    caex, pinf,
};

use crate::citp_tcp::CitpNet;

mod citp_tcp;

const CITP_HEADER_LEN: usize = 20;
const PINF_HEADER_LEN: usize = CITP_HEADER_LEN + 4;
const CAEX_HEADER_LEN: usize = CITP_HEADER_LEN + 4;
const CITP_COOKIE: u32 = u32::from_le_bytes([b'C', b'I', b'T', b'P']);

fn create_pinf_socket() -> io::Result<UdpSocket> {
    let addr = citp::pinf::OLD_MULTICAST_ADDR.into();
    let port = citp::pinf::MULTICAST_PORT;

    let recv_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    recv_socket.set_reuse_address(true)?;
    recv_socket.set_nonblocking(true)?;
    
    #[cfg(not(windows))]
    recv_socket.bind(&SocketAddrV4::new(addr, port).into())?;

    #[cfg(windows)]
    recv_socket.bind(&SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port).into())?;
    recv_socket.join_multicast_v4(&addr, &Ipv4Addr::new(0, 0, 0, 0))?;

    Ok(UdpSocket::from(recv_socket))
}

fn main() {
    let pinf_socket = create_pinf_socket().expect("Failed to create PINF socket");
    pinf_socket.set_nonblocking(false).unwrap();
    
    let mut recv_buf = vec![0u8; 1024].into_boxed_slice();

    let stream;

    loop {
        let (len, src) = pinf_socket.recv_from(&mut recv_buf)
            .expect("Failed to read from PINF socket");
        let buf = &recv_buf[..len];
        let head = citp::Header::read_from_bytes(buf).unwrap();
        let buf = &buf[CITP_HEADER_LEN..];
        if &head.content_type.to_le_bytes() != citp::pinf::Header::CONTENT_TYPE {
            eprintln!("Unexpected content type over PINF socket");
            continue;
        }
        let content_type_2 = [buf[0], buf[1], buf[2], buf[3]];
        let buf = &buf[4..];
        if &content_type_2 != citp::pinf::PLoc::CONTENT_TYPE {
            eprintln!("Unexpected PINF content type over PINF socket");
            continue;
        }
        let ploc = citp::pinf::PLoc::read_from_bytes(buf).unwrap();
        let con_addr = SocketAddr::new(src.ip(), ploc.listening_tcp_port);

        stream = TcpStream::connect(con_addr).expect("Could not connect to server");
        break;
    }

    let mut citp_tcp = CitpNet::new(stream).unwrap();
    citp_tcp.write_packet(make_pinf_pnam(c"CITP-rs Live View".into(), 38)).unwrap();

    loop {
        citp_tcp.write_packet(make_caex_get_live_view_status(42)).unwrap();
        
        while let Some((header, body)) = citp_tcp.receive_packet().unwrap() {
            if &header.content_type.to_le_bytes() != caex::Header::CONTENT_TYPE {
                // skip the message
                continue;
            }
            let content_type_2 = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            let body = &body[4..];
            match content_type_2 {
                caex::LiveViewStatus::CONTENT_TYPE => {
                    let msg = caex::LiveViewStatus::read_from_bytes(body).unwrap();
                    println!("{msg:?}");

                    citp_tcp.write_packet(make_caex_get_live_view_image(75, msg)).unwrap();
                },
                caex::LiveViewImage::CONTENT_TYPE => {
                    let msg = caex::LiveViewImage::read_from_bytes(body).unwrap();
                    fs::write("./image.jpeg", msg.data).unwrap();
                    println!("Wrote image: quitting");
                    return;
                },
                _ => ()
            }
        }
    }
    
}

fn make_pinf_header(message_length: usize, content_type: [u8; 4], message_index: u16) -> pinf::Header {
    pinf::Header {
        citp_header: citp::Header {
            cookie: CITP_COOKIE,
            version_major: 1,
            version_minor: 0,
            kind: citp::Kind { request_index: message_index },
            message_size: (PINF_HEADER_LEN + message_length) as u32,
            message_part_count: 1,
            message_part: 0,
            content_type: u32::from_le_bytes(*pinf::Header::CONTENT_TYPE),
        },
        content_type: u32::from_le_bytes(content_type),
    }
}

fn make_caex_header(message_length: usize, content_code: u32, message_index: u16) -> caex::Header {
    caex::Header {
        citp_header: citp::Header {
            cookie: CITP_COOKIE,
            version_major: 1,
            version_minor: 0,
            kind: citp::Kind { request_index: message_index },
            message_size: (CAEX_HEADER_LEN + message_length) as u32,
            message_part_count: 1,
            message_part: 0,
            content_type: u32::from_le_bytes(*caex::Header::CONTENT_TYPE),
        },
        content_type: content_code,
    }
}

fn make_pinf_pnam(name: CString, message_index: u16) -> pinf::Message<pinf::PNam> {
    let pnam = pinf::PNam {
        name,
    };
    pinf::Message {
        pinf_header: make_pinf_header(
            pnam.size_bytes(), 
            *pinf::PNam::CONTENT_TYPE,
            message_index,
        ),
        message: pnam
    }
}

fn make_caex_get_live_view_status(message_index: u16) -> caex::Message<caex::GetLiveViewStatus> {
    let stat = caex::GetLiveViewStatus {};
    caex::Message {
        caex_header: make_caex_header(
            0,
            caex::GetLiveViewStatus::CONTENT_TYPE,
            message_index,
        ),
        message: stat
    }
}

fn make_caex_get_live_view_image(message_index: u16, status: caex::LiveViewStatus) -> caex::Message<caex::GetLiveViewImage> {
    let img = caex::GetLiveViewImage {
        format: 0x01,
        resolution: status.size,
        camera_position: status.camera_position,
        camera_focus: status.camera_focus,
    };
    caex::Message {
        caex_header: make_caex_header(
            img.size_bytes(),
            caex::GetLiveViewImage::CONTENT_TYPE,
            message_index,
        ),
        message: img
    }
}
