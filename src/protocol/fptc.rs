use protocol::{self, LE, ReadBytes, ReadBytesExt, ReadFromBytes, SizeBytes, WriteBytes,
               WriteBytesExt, WriteToBytes};
use std::borrow::Cow;
use std::ffi::CString;
use std::{io, mem};

/// The FPTC layer provides a standard, single, header used at the start of all FPTC packets.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Header {
    /// The CITP header. CITP ContentType is "FPTC".
    pub citp_header: protocol::Header,
    /// A cookie defining which FPTC message it is.
    pub content_type: u32,
    /// Content hint flags:
    /// - 0x00000001 - Message part of a sequence of messages.
    /// - 0x00000002 - Message part of and ends a sequence of messages.
    pub content_hint: u32,
}

/// Layout of FPTC messages.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Message<T> {
    /// The FPTC header - the base header with the FPTC content type.
    pub fptc_header: Header,
    /// The data for the message.
    pub message: T,
}

/// ## FPTC / Ptch - Patch message.
///
/// Patch messages are sent when fixtures are introduced or repatched. The patch message contains
/// the identifier of the fixture added, the sender fixture (library) type make and name of the
/// fixture added and the patching information.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Ptch {
    /// Fixture identifier.
    pub fixture_identifier: u16,
    /// Patch universe (`0`-based).
    pub universe: u8,
    /// 4-byte aligment.
    pub reserved: u8,
    /// Patch channel (`0`-based).
    pub channel: u16,
    /// Patch channel count (`1`-`512`).
    pub channel_count: u16,
    /// Fixture make (only `null` if omitted).
    pub fixture_make: CString,
    /// Fixture name (never omitted).
    pub fixture_name: CString,
}

/// ## FPTC / UPtc - Unpatch message
///
/// Unpatch messages are sent when fixtures are deleted or unpatched. The unpatch message only
/// contains the identifiers of the fixtures removed. An empty fixture identifier array indicates
/// complete unpatching.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct UPtc<'a> {
    /// Specific fixtures to unpatch.
    pub fixture_identifiers: Cow<'a, [u16]>,
}

/// ## FPTC / SPtc - SendPatch message
///
/// The SendPatch message instructs the receiver to send Patch messages in response, one for each
/// fixture specified in the `fixture_identifiers` slice. If no fixture identifiers are specified,
/// the entire **Patch** should be transferred in response. This procedure can be used for testing
/// existence of fixtures on the remote side or to synchronise the entire patch information.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SPtc<'a> {
    /// Specific fixtures to unpatch.
    pub fixture_identifiers: Cow<'a, [u16]>,
}

impl Header {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"FPTC";
}

impl Ptch {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"Ptch";
}

impl<'a> UPtc<'a> {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"UPtc";
}

impl<'a> SPtc<'a> {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"SPtc";
}

impl WriteToBytes for Header {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(&self.citp_header)?;
        writer.write_u32::<LE>(self.content_type)?;
        writer.write_u32::<LE>(self.content_hint)?;
        Ok(())
    }
}

impl<T> WriteToBytes for Message<T>
where
    T: WriteToBytes,
{
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(&self.fptc_header)?;
        writer.write_bytes(&self.message)?;
        Ok(())
    }
}

impl WriteToBytes for Ptch {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.fixture_identifier)?;
        writer.write_u8(self.universe)?;
        writer.write_u8(self.reserved)?;
        writer.write_u16::<LE>(self.channel)?;
        writer.write_u16::<LE>(self.channel_count)?;
        writer.write_bytes(&self.fixture_make)?;
        writer.write_bytes(&self.fixture_name)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for UPtc<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.fixture_identifiers.len() as _)?;
        for &id in self.fixture_identifiers.iter() {
            writer.write_u16::<LE>(id)?;
        }
        Ok(())
    }
}

impl<'a> WriteToBytes for SPtc<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.fixture_identifiers.len() as _)?;
        for &id in self.fixture_identifiers.iter() {
            writer.write_u16::<LE>(id)?;
        }
        Ok(())
    }
}

impl ReadFromBytes for Ptch {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let fixture_identifier = reader.read_u16::<LE>()?;
        let universe = reader.read_u8()?;
        let reserved = reader.read_u8()?;
        let channel = reader.read_u16::<LE>()?;
        let channel_count = reader.read_u16::<LE>()?;
        let fixture_make = reader.read_bytes()?;
        let fixture_name = reader.read_bytes()?;
        let ptch = Ptch {
            fixture_identifier,
            universe,
            reserved,
            channel,
            channel_count,
            fixture_make,
            fixture_name,
        };
        Ok(ptch)
    }
}

impl ReadFromBytes for UPtc<'static> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let fixture_count: u16 = reader.read_bytes()?;
        let fixture_identifiers = protocol::read_new_vec(reader, fixture_count as _)?;
        let fixture_identifiers = Cow::Owned(fixture_identifiers);
        let uptc = UPtc { fixture_identifiers };
        Ok(uptc)
    }
}

impl ReadFromBytes for SPtc<'static> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let fixture_count: u16 = reader.read_bytes()?;
        let fixture_identifiers = protocol::read_new_vec(reader, fixture_count as _)?;
        let fixture_identifiers = Cow::Owned(fixture_identifiers);
        let uptc = SPtc { fixture_identifiers };
        Ok(uptc)
    }
}

impl SizeBytes for Ptch {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u16>()
        + mem::size_of::<u8>()
        + mem::size_of::<u8>()
        + mem::size_of::<u16>()
        + mem::size_of::<u16>()
        + self.fixture_make.size_bytes()
        + self.fixture_name.size_bytes()
    }
}

impl<'a> SizeBytes for UPtc<'a> {
    fn size_bytes(&self) -> usize {
        self.fixture_identifiers.len() * mem::size_of::<u16>()
    }
}

impl<'a> SizeBytes for SPtc<'a> {
    fn size_bytes(&self) -> usize {
        self.fixture_identifiers.len() * mem::size_of::<u16>()
    }
}
