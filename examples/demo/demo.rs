mod citp_tcp;

use crate::citp_tcp::CaexState;
use citp::protocol::{caex, pinf, ReadFromBytes, SizeBytes, Ucs2, WriteToBytes};
use citp_tcp::CitpTcp;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    borrow::Cow,
    ffi::CString,
    io::{self, Write},
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    str::FromStr,
};

pub const CITP_HEADER_LEN: usize = 20;
pub const CONTENT_TYPE_LEN: usize = 4;
pub const NUM_LASERS: i32 = 1;

#[derive(Debug)]
enum State {
    Init,
    Connect,
    Request,
    Stream,
}

fn main() -> io::Result<()> {
    let mut state = State::Init;
    let mut citp_tcp_stream: Option<CitpTcp> = None;
    let mut buf: [MaybeUninit<u8>; 65535] = unsafe { MaybeUninit::uninit().assume_init() };
    let mut frame_num = 0;
    let source_key = rand::random::<u32>();

    let addr = citp::protocol::pinf::OLD_MULTICAST_ADDR;
    let port = citp::protocol::pinf::MULTICAST_PORT;
    let multicast_address = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    let destination = SocketAddr::new(IpAddr::V4(multicast_address), port);

    // Sending socket
    let send_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    // Receiving socket
    let recv_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    recv_socket.set_reuse_address(true)?;
    recv_socket.set_nonblocking(true)?;
    recv_socket.bind(&SocketAddrV4::new(multicast_address, port).into())?;

    loop {
        match state {
            State::Init => match recv_socket
                .join_multicast_v4(&multicast_address, &Ipv4Addr::new(0, 0, 0, 0))
            {
                Ok(_) => {
                    state = State::Connect;
                }
                Err(err) => eprintln!("join_multicast_v4 {:?}", err),
            },
            State::Connect => {
                match recv_socket.recv_from(&mut buf) {
                    Ok((len, ..)) => {
                        // - Read the full base **Header** first.
                        let data = to_data(&mut buf, len);
                        let header = citp::protocol::Header::read_from_bytes(data)?;
                        let header_size = header.size_bytes();

                        match &header.content_type.to_le_bytes() {
                            pinf::Header::CONTENT_TYPE => {
                                if let pinf::PLoc::CONTENT_TYPE =
                                    &layer_two_content_type(&data, header_size).to_le_bytes()
                                {
                                    let ploc = citp::protocol::pinf::PLoc::read_from_bytes(
                                        &data[header_size + CONTENT_TYPE_LEN..],
                                    )?;
                                    let name = ploc.name.to_str().unwrap().to_owned();
                                    let tcp_addr = format!(
                                        "{}:{}",
                                        extract_ip_address(&name),
                                        ploc.listening_tcp_port
                                    );

                                    let stream = TcpStream::connect(tcp_addr)
                                        .expect("Could not connect to server");
                                    let mut citp_tcp = CitpTcp::new(stream)?;
                                    let pnam_message = connect_to_capture();
                                    pnam_message
                                        .write_to_bytes(&mut citp_tcp.writer)
                                        .expect("Failed to write to server");

                                    // Tell TCP to send the buffered data on the wire
                                    citp_tcp.writer.flush()?;
                                    citp_tcp_stream = Some(citp_tcp);
                                    state = State::Request;
                                }
                            }
                            _ => eprintln!("Connect: Unrecognized UDP Header Content Type"),
                        }
                    }
                    Err(_) => {}
                }
            }
            State::Request => {
                send_peer_location(&send_socket, destination);
                if let Some(ref mut stream) = citp_tcp_stream {
                    let caex_state = stream.read_message()?;
                    if let Some(CaexState::EnterShow) = caex_state {
                        let enter_show = enter_show("kortex-test-suite");
                        enter_show
                            .write_to_bytes(&mut stream.writer)
                            .expect("Failed to write to server");
                        stream.writer.flush()?;
                    }
                    if let Some(CaexState::GetLaserFeedList) = caex_state {
                        let feed_list = send_laser_feed_list(source_key);
                        feed_list
                            .write_to_bytes(&mut stream.writer)
                            .expect("Failed to write to server");
                        stream.writer.flush()?;
                    }
                    if let Some(CaexState::FixtureListRequest) = caex_state {
                        let fixture_list = new_fixture_list();
                        fixture_list
                            .write_to_bytes(&mut stream.writer)
                            .expect("Failed to write to server");
                        stream.writer.flush()?;
                        state = State::Stream;
                    }
                }
            }
            State::Stream => {
                if frame_num % 100 == 0 {
                    send_peer_location(&send_socket, destination);
                }

                for i in 0..NUM_LASERS {
                    let laser_frame = stream_laser_frame(source_key, frame_num, i as u8);
                    let mut frame_buf = [0u8; 65535];
                    laser_frame
                        .write_to_bytes(&mut frame_buf[..])
                        .expect("Failed to write to server");
                    let len = laser_frame.caex_header.citp_header.message_size as usize;
                    send_socket
                        .send_to(&frame_buf[..len], &SockAddr::from(destination))
                        .expect("Can't send buffer over UDP Socket");
                }
                frame_num += 1;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(16));
    }
}

pub fn layer_two_content_type(data: &[u8], header_size: usize) -> u32 {
    let slice = &data[header_size..header_size + CONTENT_TYPE_LEN];
    u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
}

fn pinf_header(pinf_message_size: usize, content_type: u32) -> pinf::Header {
    pinf::Header {
        citp_header: citp::protocol::Header {
            cookie: u32::from_le_bytes(*b"CITP"),
            version_major: 1,
            version_minor: 0,
            kind: citp::protocol::Kind { request_index: 0 },
            message_size: (CITP_HEADER_LEN + CONTENT_TYPE_LEN + pinf_message_size) as u32,
            message_part_count: 1,
            message_part: 0,
            content_type: u32::from_le_bytes(*pinf::Header::CONTENT_TYPE),
        },
        content_type,
    }
}

fn peer_location() -> pinf::Message<pinf::PLoc> {
    let error_msg = "CString::new failed";
    let ploc = pinf::PLoc {
        listening_tcp_port: 0,
        kind: CString::new("LightingConsole").expect(error_msg),
        name: CString::new("Rusty Previz Tool").expect(error_msg),
        state: CString::new("Firing ze lasers").expect(error_msg),
    };
    pinf::Message {
        pinf_header: pinf_header(
            ploc.size_bytes(),
            u32::from_le_bytes(*pinf::PLoc::CONTENT_TYPE),
        ),
        message: ploc,
    }
}

// Regularly send a CITP/PINF/PLoc message with no listening port.
fn send_peer_location(send_socket: &Socket, destination: SocketAddr) {
    let ploc = peer_location();
    let mut ploc_buf = [0u8; 65535];
    match ploc.write_to_bytes(&mut ploc_buf[..]) {
        Ok(_) => {
            let len = ploc.pinf_header.citp_header.message_size as usize;
            send_socket
                .send_to(&ploc_buf[..len], &SockAddr::from(destination))
                .expect("Can't send buffer over UDP Socket");
        }
        Err(_) => {
            eprintln!("error writing ploc to bytes");
        }
    }
}

fn connect_to_capture() -> pinf::Message<pinf::PNam> {
    let pnam = pinf::PNam {
        name: CString::new("Rusty Laser Software").expect("CString::new failed"),
    };
    pinf::Message {
        pinf_header: pinf_header(
            pnam.size_bytes(),
            u32::from_le_bytes(*pinf::PNam::CONTENT_TYPE),
        ),
        message: pnam,
    }
}

fn enter_show(project_name: &str) -> caex::Message<caex::EnterShow> {
    let enter_show = caex::EnterShow {
        name: citp::protocol::Ucs2::from_str(project_name).unwrap(),
    };
    caex::Message {
        caex_header: caex_header(enter_show.size_bytes(), caex::EnterShow::CONTENT_TYPE),
        message: enter_show,
    }
}

fn caex_header(caex_message_size: usize, content_type: u32) -> caex::Header {
    caex::Header {
        citp_header: citp::protocol::Header {
            cookie: u32::from_le_bytes(*b"CITP"),
            version_major: 1,
            version_minor: 0,
            kind: citp::protocol::Kind { request_index: 0 },
            message_size: (CITP_HEADER_LEN + CONTENT_TYPE_LEN + caex_message_size) as u32,
            message_part_count: 1,
            message_part: 0,
            content_type: u32::from_le_bytes(*b"CAEX"),
        },
        content_type,
    }
}

fn send_laser_feed_list<'a>(source_key: u32) -> caex::Message<caex::LaserFeedList<'a>> {
    let mut test_list = vec![];
    for i in 0..NUM_LASERS {
        let name = format!("rusty_laser {}", i);
        let ucs2 = Ucs2::from_str(name.as_str()).unwrap();
        test_list.push(ucs2);
    }
    let feed_list = caex::LaserFeedList {
        source_key: source_key,
        feed_count: test_list.len() as u8,
        feed_names: std::borrow::Cow::from(test_list),
    };
    caex::Message {
        caex_header: caex_header(feed_list.size_bytes(), caex::LaserFeedList::CONTENT_TYPE),
        message: feed_list,
    }
}

fn stream_laser_frame<'a>(
    source_key: u32,
    frame_num: u32,
    feed_index: u8,
) -> caex::Message<caex::LaserFeedFrame<'a>> {
    let tl = [-1.0, 1.0];
    let tr = [1.0, 1.0];
    let br = [1.0, -1.0];
    let bl = [-1.0, -1.0];
    let positions = [tl, tr, br, bl, tl];
    let points: Vec<_> = positions
        .iter()
        .cloned()
        .map(|p| {
            let scale = (feed_index as f32 + frame_num as f32 * 0.002).sin();
            let x = map_range(p[0] * scale, -1.0, 1.0, 0.0, 4093.0);
            let y = map_range(p[1] * scale, -1.0, 1.0, 0.0, 4093.0);
            let x_nibble = (x / 256.0).floor() as u8 % 16;
            let y_nibble = (y / 256.0).floor() as u8 % 16;
            let xy_high_nibbles = y_nibble * 16 + x_nibble;

            let lfo1 = (feed_index as f32 + frame_num as f32 * 0.04).sin().abs();
            let lfo2 = (feed_index as f32 + frame_num as f32 * 0.015).sin().abs();
            let lfo3 = (feed_index as f32 + frame_num as f32 * 0.02).cos().abs();

            let r = map_range(lfo1, 0.0, 1.0, 0.0, 31.0) as u8;
            let g = map_range(lfo2, 0.0, 1.0, 0.0, 63.0) as u8;
            let b = map_range(lfo3, 0.0, 1.0, 0.0, 31.0) as u8;

            let color = r as u16 | (g as u16).rotate_left(5) | (b as u16).rotate_left(11);

            caex::LaserPoint {
                x_low_byte: (x % 256.0) as u8,
                y_low_byte: (y % 256.0) as u8,
                xy_high_nibbles,
                color,
            }
        })
        .collect();

    let feed_frame = caex::LaserFeedFrame {
        source_key,
        feed_index,
        frame_sequence: frame_num,
        point_count: points.len() as u16,
        points: std::borrow::Cow::from(points),
    };
    caex::Message {
        caex_header: caex_header(feed_frame.size_bytes(), caex::LaserFeedFrame::CONTENT_TYPE),
        message: feed_frame,
    }
}

fn new_fixture_list<'a>() -> caex::Message<caex::FixtureList<'a>> {
    let fixture_list = caex::FixtureList {
        message_type: caex::FixtureListMessageType::ExistingPatchList,
        fixture_count: 0,
        fixtures: Cow::Owned(vec![]),
    };
    caex::Message {
        caex_header: caex_header(fixture_list.size_bytes(), caex::FixtureList::CONTENT_TYPE),
        message: fixture_list,
    }
}

fn extract_ip_address(s: &String) -> String {
    let start_bytes = s.find("(").unwrap_or(0) + 1;
    let end_bytes = s.find(")").unwrap_or(s.len());
    s[start_bytes..end_bytes].to_string()
}

fn to_data(buf: &mut [MaybeUninit<u8>], len: usize) -> &[u8] {
    let ptr = buf.as_mut_ptr() as *mut u8;
    unsafe { std::slice::from_raw_parts_mut(ptr, len) }
}

/// Map a value from a given range to a new given range.
pub fn map_range(val: f32, in_min: f32, in_max: f32, out_min: f32, out_max: f32) -> f32 {
    (val - in_min) / (in_max - in_min) * (out_max - out_min) + out_min
}
