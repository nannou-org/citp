use crate::protocol::{
    self, ReadBytesExt, ReadFromBytes, SizeBytes, WriteBytes, WriteBytesExt, WriteToBytes, LE,
};
use std::borrow::Cow;
use std::{io, mem};

/// The FSEL layer provides a standard, single, header used at the start of all FSEL packets.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Header {
    /// The CITP header. CITP ContentType is "FPTC".
    pub citp_header: protocol::Header,
    /// A cookie defining which FSEL message it is.
    pub content_type: u32,
}

/// Layout of FSEL messages.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Message<T> {
    /// The FSEL header - the base header with the FSEL content type.
    pub fsel_header: Header,
    /// The data for the message.
    pub message: T,
}

/// ## FSEL / Sele - Select message
///
/// The Select mesesage instructs the receiver to select a number of fixtures. If the `complete`
/// field is non-zero, only the fixtures identified in the message should be selected and all
/// others should be deselected, thus achieving a full synchronisation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Sele<'a> {
    /// Set to non-zero for complete selection.
    pub complete: u8,
    /// 4-byte alignment.
    pub reserved: u8,
    /// List of fixture identifiers.
    pub fixture_identifiers: Cow<'a, [u16]>,
}

/// ## FSEL / DeSe - Deselect message
///
/// The Deselect message acts similarly to the Select message. However, a Deselect message
/// deselects the fixture specified, rather than selecting them. A Deselect with no fixture
/// specified should deselect all fixtures.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct DeSe<'a> {
    /// List of fixture identifiers.
    pub fixture_identifiers: Cow<'a, [u16]>,
}

impl Header {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"FSEL";
}

impl<'a> Sele<'a> {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"Sele";
}

impl<'a> DeSe<'a> {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"DeSe";
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
        writer.write_bytes(self.fsel_header)?;
        writer.write_bytes(&self.message)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for Sele<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.complete)?;
        writer.write_u8(self.reserved)?;
        writer.write_u16::<LE>(self.fixture_identifiers.len() as _)?;
        for &id in self.fixture_identifiers.iter() {
            writer.write_u16::<LE>(id)?;
        }
        Ok(())
    }
}

impl<'a> WriteToBytes for DeSe<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.fixture_identifiers.len() as _)?;
        for &id in self.fixture_identifiers.iter() {
            writer.write_u16::<LE>(id)?;
        }
        Ok(())
    }
}

impl ReadFromBytes for Sele<'static> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let complete = reader.read_u8()?;
        let reserved = reader.read_u8()?;
        let fixture_count = reader.read_u16::<LE>()?;
        let fixture_identifiers = protocol::read_new_vec(reader, fixture_count as _)?;
        let fixture_identifiers = Cow::Owned(fixture_identifiers);
        let sele = Sele {
            complete,
            reserved,
            fixture_identifiers,
        };
        Ok(sele)
    }
}

impl ReadFromBytes for DeSe<'static> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let fixture_count = reader.read_u16::<LE>()?;
        let fixture_identifiers = protocol::read_new_vec(reader, fixture_count as _)?;
        let fixture_identifiers = Cow::Owned(fixture_identifiers);
        let dese = DeSe {
            fixture_identifiers,
        };
        Ok(dese)
    }
}

impl<'a> SizeBytes for Sele<'a> {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>()
            + mem::size_of::<u8>()
            + mem::size_of::<u16>()
            + self.fixture_identifiers.len() * mem::size_of::<u16>()
    }
}

impl<'a> SizeBytes for DeSe<'a> {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u16>() + self.fixture_identifiers.len() * mem::size_of::<u16>()
    }
}
