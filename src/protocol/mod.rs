//! ## Protocol Types, Readers and Writers.
//!
//! All CITP protocol types can be written-to and read-from little-endian bytes using the
//! **WriteBytes** and **ReadBytes** traits respectively. These traits are implemented for all
//! types implementing the **std::io** **Write** and **Read** traits.
//!
//! Each layer of the protocol has it's own module. The "Base layer" is specified within this
//! module.
//!
//! *Note that not all types within these modules have a layout that exactly matches the C
//! specification, however the **WriteToBytes** and **ReadFromBytes** implementations should match
//! exactly. This is because some types can be much better expressed in rust via the std slice
//! types rather than separate "counter" and array pointer fields which require `unsafe` blocks to
//! use.*
//!
//! ## CITP - Base Layer
//!
//! This module also specifies the base layer as described within the protocol. The base layaer
//! does not define any packages, it merely adds a header that encapsulate all messages.
//!
//! ## Reading a Stream.
//!
//! To read the protocol from a stream of little endian bytes where the received messages are not
//! known ahead of time, the following steps may be followed:
//!
//! - Read the full base **Header** first.
//! - Match on the `content_type` field to determine the next layer to read.
//! - Read the header for the second layer.
//! - Match on the `content_type` field of the second layer to determine what type to read.

pub use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::ffi::CString;
use std::hash::{Hash, Hasher};
use std::{fmt, io, mem};

/// ## CITP/PINF - Peer Information Layer
///
/// The Peer Information Layer is used to exchange peer information, both when connected and during
/// discovery.
///
/// The PINF/PNam message was originally broadcasted on UDP port 4810 as a means of discovery. This
/// was then replaced with the PINF/PLoc message being multicasted on address 244.0.0.180, port
/// 4809 instead. Since early 2014, the multicast address was changed to 239.224.0.180 with the
/// recommendation that systems also support using the previous 224.0.0.180 address during a
/// transitional period.
///
/// Once two peers have established a direct TCP connection, a PINF/PName message should
/// immediately be sent as the first message.
pub mod pinf;

/// The SDMX layer is used to transmit DMX information. CITP supports transmitting a single - wide
/// - universe of DMX channels with at most 65_536 channels. It also supports designating an
/// alternative DMX source such as ArtNet or ETCNet2 (see "connection strings").
pub mod sdmx;

/// ## CITP/FPTC - Fixture patch layer
///
/// The Fixture Patch layer is used to communicate fixture existence and patch information.
/// Fixtures are identified by 16-bit unsigned integers with a range of valid values between 1 and
/// 65535. In most consoles this value maps directly to a "Channel", "Unit" or "Device".
///
/// The FPTC layer is built on the following design decisions:
///
/// - Unpatched fixtures do not exist from the FPTC layer's point of view. When a fixture is
///   unpatched using the `UnPatch` message, it is deleted and seizes to exist. However, the
///   fixture may continue to live in the visualiser or the console, without association to a
///   universe.  Whenever the fixture is associated with a universe again, it is reintroduced
///   through the `Patch` message.
/// - When a fixture is repatched (ie. moved to another channel or universe) it does not pass
///   through an unpatched state.
/// - In the visualiser, it may possible to change the mode of a fixture. Different modes for one
///   fixture usually use different amounts of channels, however sometimes a different mode ony
///   changes the interpretation of one or more control channels. When a mode is changed in the
///   visualiser, an unpatch message is not sent, only a new patch message. If the new mode
///   consumes a different amount of channels, this can be told by the `ChannelCount` field of the
///   patch message. If it does not, there is no way of telling.
/// - A fixture can change its patch and mode, but never its make or name. The visualiser attempts
///   to map the fixture make and name against its library.
/// - Fixture identifiers must be persistent. When both the visualiser and the console have
///   reloaded a pair of matching projects, the fixture identifiers must still be the same.
/// - When a project is closed on either side, fixtures are not unpatched. The same applies to when
///   a universe in the visualiser is deleted or unassociated with a console.
/// - No synchronisation mechanism exists in CITP, which communicates project closing/opening
///   information. This must be handled by the user by opening and closing matching projects
///   simultaneously.
/// - When the visualiser or console takes automatic actions as a result of incoming patch
///   messages, it must not result in an echo.
pub mod fptc;

/// ## CITP/FSEL - Fixture Selection layer
///
/// The Fixture Selection layer is used to carry fixture selection information. Fixture
/// identification is discussed in the `fptc` documentation.
pub mod fsel;

/// ## CITP/FINF - Fixture Information layer
///
/// The Fixture Information layer is used to carry additional fixture information. Fixture
/// identification is discussed within the `fptc` documentation.
pub mod finf;

/// ## CITP/MSEX - Media Server Extensions layer
///
/// The Media Server EXtensions layer is used for communication with media servers.
///
/// For information about how peers find eachother and connect, see the Connectivity section.
/// Typically all packets are sent over a peer-to-peer TCP socket connection, except for the
/// MSEX/StFr message which is sent over the multicast address for all to process.
///
/// ### MSEX Versions
///
/// Currently acknowledged versions of MSEX are 1.0, 1.1 and 1.2. During a session, the appropriate
/// MSEX version that is common to both sides must be established and used for all communication -
/// different versions cannot be mixed in a single session. See the MSEX/SInf and MSEX/CInf
/// messages also regarding supported version signaling.
///
/// Prior to MSEX 1.2 it was expected that all client and server implementations check the MSEX
/// version of all received messages to ensure that the message format is acceptable. Starting with
/// MSEX 1.2 this is a mandatory requirement.
///
/// There is no requirement for an implementation of a specific MSEX version to support any
/// previous MSEX versions, for this reason the version returned by the MSEX/SInf message must be
/// used for all communication by both sides.
///
/// ### Establishing Connections
///
/// Prior to MSEX 1.2, a media server was expected to send a MSEX/SInf Server Information message
/// immediately after connecting to a lighting console or visualiser. This approach has the
/// drawback that the MSEX/SInf message format has to be fixed since the media server is unaware of
/// what MSEX version(s) the other side supports. Starting with MSEX 1.2, the lighting console or
/// visualiser must send a MSEX/CInf Client Information message to the server immediately after
/// connecting, and the server will respond with a version 1.2 or later MSEX/SInf message.
///
/// NB: Although the MSEX/CInf message format must be fixed, provision has been made to allow extra
/// data to be appended as a future-proofing measure.
///
/// ### Highest Common MSEX Version
///
/// For MSEX 1.2 and later, the server must establish the Highest Common MSEX Version when a
/// MSEX/CInf is received from a newly connected lighting console or media server. This is the
/// highest MSEX version that is supported on both sides, and must be used for all unsolicited
/// messages, such as MSEX/SInf, MSEX/LSta and MSEX/ELUp. The Highest Common MSEX version is at
/// least 1.2.
///
/// ### Mandatory messages
///
/// Implementations can choose to implement a subset of MSEX messages to suit their needs, but some
/// messages are essential for correct interoperation and are marked as mandatory. The mandatory
/// messages are:
///
/// 1. CInf - Client Information message
/// 2. SInf - Server Information message
/// 3. LSta - Layer Status message
/// 4. Nack - Negative acknowledge message
///
/// ### Image formats
///
/// MSEX supports three image formats for thumbnails and five image formats for video stream
/// frames:
///
/// - RGB8 - a raw array of 8-byte RGB triples (this is **not** BMP). In MSEX 1.0 the byte order
/// was BGR, but from MSEX 1.1 the byte order is RGB.
/// - JPEG - the well known file format (which does **not** include EXIF).
/// - PNG - the well known file format. Requires MSEX 1.2.
/// - Fragmented JPB - JPEG data fragments (for streams only). Requires MSEX 1.2.
/// - Fragmented PNG - PNG data fragments (for streams oly). Requires MSEX 1.2.
pub mod msex;

/// A trait for writing any of the CITP protocol types to little-endian bytes.
///
/// A blanket implementation is provided for all types that implement `byteorder::WriteBytesExt`.
pub trait WriteBytes {
    fn write_bytes<P: WriteToBytes>(&mut self, protocol: P) -> io::Result<()>;
}

/// A trait for reading any of the CITP protocol types from little-endian bytes.
///
/// A blanket implementation is provided for all types that implement `byteorder::ReadBytesExt`.
pub trait ReadBytes {
    fn read_bytes<P: ReadFromBytes>(&mut self) -> io::Result<P>;
}

/// Protocol types that may be written to little endian bytes.
pub trait WriteToBytes {
    /// Write the command to bytes.
    fn write_to_bytes<W: WriteBytesExt>(&self, writer: W) -> io::Result<()>;
}

/// Protocol types that may be read from little endian bytes.
pub trait ReadFromBytes: Sized {
    /// Read the command from bytes.
    fn read_from_bytes<R: ReadBytesExt>(reader: R) -> io::Result<Self>;
}

/// Types that have a constant size when written to or read from bytes.
pub trait ConstSizeBytes: SizeBytes {
    const SIZE_BYTES: usize;
}

/// Types whose size when written to bytes may be determined at runtime.
pub trait SizeBytes {
    fn size_bytes(&self) -> usize;
}

/// The CITP layer provides a standard, single, header used at the start of all CITP packets.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Header {
    /// Set to "CITP"
    pub cookie: u32,
    /// Set to 1.
    pub version_major: u8,
    /// Set to 0.
    pub version_minor: u8,
    /// These allow request/response message pairs to be better associated and is particularly useful
    /// for debugging purposes. A node that sends request messages (such as a Lighting Console
    /// requesting info from a Media Server) should maintain a request counter, and increment this with
    /// every request message sent. When the other side sends a response to a specific request message,
    /// it should set this field to the same value as was found in the corresponding request message.
    ///
    /// The value of `0` is taken to mean `ignored`, so proper `RequestIndex` values should start
    /// at `1` (and wrap back around to `1`, avoiding the `0` "ignored" value). This was introduced
    /// for MSEX 1.2 and was previously a reserved 2-byte alignment field.
    pub kind: Kind,
    /// The size of the entire message, including this header.
    pub message_size: u32,
    /// Number of message fragments.
    pub message_part_count: u16,
    /// Index of this message fragment (0-based).
    pub message_part: u16,
    /// Cookie identifying the type of contents (the name of the second layer).
    pub content_type: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union Kind {
    request_index: u16,
    in_response_to: u16,
}

impl WriteToBytes for Kind {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        unsafe { writer.write_u16::<LE>(self.request_index) }
    }
}

impl WriteToBytes for Header {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<LE>(self.cookie)?;
        writer.write_u8(self.version_major)?;
        writer.write_u8(self.version_minor)?;
        writer.write_bytes(self.kind)?;
        writer.write_u32::<LE>(self.message_size)?;
        writer.write_u16::<LE>(self.message_part_count)?;
        writer.write_u16::<LE>(self.message_part)?;
        writer.write_u32::<LE>(self.content_type)?;
        Ok(())
    }
}

impl ReadFromBytes for Kind {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let request_index = reader.read_u16::<LE>()?;
        Ok(Kind { request_index })
    }
}

impl ReadFromBytes for Header {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let cookie = reader.read_u32::<LE>()?;
        let version_major = reader.read_u8()?;
        let version_minor = reader.read_u8()?;
        let kind = reader.read_bytes()?;
        let message_size = reader.read_u32::<LE>()?;
        let message_part_count = reader.read_u16::<LE>()?;
        let message_part = reader.read_u16::<LE>()?;
        let content_type = reader.read_u32::<LE>()?;
        let header = Header {
            cookie,
            version_major,
            version_minor,
            kind,
            message_size,
            message_part_count,
            message_part,
            content_type,
        };
        Ok(header)
    }
}

impl<W> WriteBytes for W
where
    W: WriteBytesExt,
{
    fn write_bytes<P: WriteToBytes>(&mut self, protocol: P) -> io::Result<()> {
        protocol.write_to_bytes(self)
    }
}

impl<R> ReadBytes for R
where
    R: ReadBytesExt,
{
    fn read_bytes<P: ReadFromBytes>(&mut self) -> io::Result<P> {
        P::read_from_bytes(self)
    }
}

impl<'a, T> WriteToBytes for &'a T
where
    T: WriteToBytes,
{
    fn write_to_bytes<W: WriteBytesExt>(&self, writer: W) -> io::Result<()> {
        (**self).write_to_bytes(writer)
    }
}

impl WriteToBytes for CString {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        let bytes = self.as_bytes_with_nul();
        for &byte in bytes {
            writer.write_u8(byte)?;
        }
        Ok(())
    }
}

impl ReadFromBytes for CString {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let mut bytes = vec![];
        loop {
            match reader.read_u8()? {
                b'\0' => break,
                byte => bytes.push(byte),
            }
        }
        let cstring = unsafe { CString::from_vec_unchecked(bytes) };
        Ok(cstring)
    }
}

impl ReadFromBytes for u8 {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        reader.read_u8()
    }
}

impl ReadFromBytes for u16 {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        reader.read_u16::<LE>()
    }
}

impl SizeBytes for CString {
    fn size_bytes(&self) -> usize {
        self.as_bytes_with_nul().len()
    }
}

impl SizeBytes for Kind {
    fn size_bytes(&self) -> usize {
        mem::size_of::<Kind>()
    }
}

impl SizeBytes for Header {
    fn size_bytes(&self) -> usize {
        mem::size_of::<Header>()
    }
}

impl fmt::Debug for Kind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe { write!(f, "{:?}", self.request_index) }
    }
}

impl Eq for Kind {}

impl PartialEq for Kind {
    fn eq(&self, other: &Self) -> bool {
        unsafe { self.request_index == other.request_index }
    }
}

impl Hash for Kind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        unsafe {
            self.request_index.hash(state);
        }
    }
}

/// Read **len** elements of type **T** into the given **vec**.
pub fn read_vec<R, T>(mut reader: R, mut len: usize, vec: &mut Vec<T>) -> io::Result<()>
where
    R: ReadBytesExt,
    T: ReadFromBytes,
{
    while len > 0 {
        let elem = reader.read_bytes()?;
        vec.push(elem);
        len -= 1;
    }
    Ok(())
}

/// Read **len** elements of type **T** into a new **Vec**.
pub fn read_new_vec<R, T>(reader: R, len: usize) -> io::Result<Vec<T>>
where
    R: ReadBytesExt,
    T: ReadFromBytes,
{
    let mut vec = Vec::with_capacity(len);
    read_vec(reader, len, &mut vec)?;
    Ok(vec)
}
