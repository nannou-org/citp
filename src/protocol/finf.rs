use crate::protocol::{self, LE, ReadBytes, ReadBytesExt, ReadFromBytes, SizeBytes, WriteBytes,
               WriteBytesExt, WriteToBytes};
use std::borrow::Cow;
use std::ffi::CString;
use std::{io, mem};

/// The FINF layer provides a standard, single, header used at the start of all FINF packets.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Header {
    /// The CITP header. CITP ContentType is "FINF".
    pub citp_header: protocol::Header,
    /// A cookie defining which FINF message it is.
    pub content_type: u32,
}

/// Layout of FINF messages.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Message<T> {
    /// The FINF header - the base header with the FINF content type.
    pub finf_header: Header,
    /// The data for the message.
    pub message: T,
}

/// ## FINF / SFra - Send Frames message
///
/// This message informs the receiver to send frame messages for the specified fixtures.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SFra<'a> {
    /// List of fixture identifiers.
    pub fixture_identifiers: Cow<'a, [u16]>,
}

/// ## FINF / FRAM - Frames message
///
/// This message informs the receiver about the filters & gobos of a fixture.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Fram {
    /// The fixture identifier.
    pub fixture_identifier: u16,
    /// Number of filters in the `frame_names` field.
    pub frame_filter_count: u8,
    /// Number of gobos in the `gobos` field.
    pub frame_gobo_count: u8,
    /// List of (first) filters and (last) gobos, newline separated (\n) & null terminated.
    ///
    /// Always contains *at least* the null.
    pub frame_names: CString,
}

impl Header {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"FINF";
}

impl<'a> SFra<'a> {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"SFra";
}

impl Fram {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"Fram";
}

impl WriteToBytes for Header {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(self.citp_header)?;
        writer.write_u32::<LE>(self.content_type)?;
        Ok(())
    }
}

impl<T> WriteToBytes for Message<T>
where
    T: WriteToBytes,
{
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(self.finf_header)?;
        writer.write_bytes(&self.message)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for SFra<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.fixture_identifiers.len() as _)?;
        for &id in self.fixture_identifiers.iter() {
            writer.write_u16::<LE>(id)?;
        }
        Ok(())
    }
}

impl WriteToBytes for Fram {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.fixture_identifier)?;
        writer.write_u8(self.frame_filter_count)?;
        writer.write_u8(self.frame_gobo_count)?;
        writer.write_bytes(&self.frame_names)?;
        Ok(())
    }
}

impl ReadFromBytes for SFra<'static> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let fixture_count = reader.read_u16::<LE>()?;
        let fixture_identifiers = protocol::read_new_vec(reader, fixture_count as _)?;
        let fixture_identifiers = Cow::Owned(fixture_identifiers);
        let sfra = SFra { fixture_identifiers };
        Ok(sfra)
    }
}

impl ReadFromBytes for Fram {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let fixture_identifier = reader.read_u16::<LE>()?;
        let frame_filter_count = reader.read_u8()?;
        let frame_gobo_count = reader.read_u8()?;
        let frame_names = reader.read_bytes()?;
        let fram = Fram { fixture_identifier, frame_filter_count, frame_gobo_count, frame_names };
        Ok(fram)
    }
}

impl<'a> SizeBytes for SFra<'a> {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u16>()
        + self.fixture_identifiers.len() * mem::size_of::<u16>()
    }
}

impl SizeBytes for Fram {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u16>()
        + mem::size_of::<u8>()
        + mem::size_of::<u8>()
        + self.frame_names.size_bytes()
    }
}
