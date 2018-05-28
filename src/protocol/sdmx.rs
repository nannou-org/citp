use protocol::{self, LE, ReadBytes, ReadBytesExt, ReadFromBytes, SizeBytes, WriteBytes,
               WriteBytesExt, WriteToBytes};
use std::borrow::Cow;
use std::ffi::CString;
use std::{self, io, mem};

/// ## The SDMX header.
///
/// The SDMX layer provides a standard, single, header used at the start of all SDMX packets.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Header {
    /// The CITP header. CITP ContentType is "SDMX".
    pub citp_header: protocol::Header,
    /// Cookie defining which SDMX message it is.
    pub content_type: u32,
}

/// SDMX messages are always prefixed with a CITP SDMX header.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Message<T> {
    /// The base header along with the SDMX content type.
    pub sdmx_header: Header,
    /// The unique contents of the message.
    pub message: T,
}

/// ## SDMX / Capa - Capabilities message.
///
/// The capabilities message can be sent by a peer to the remote peer upon connect to inform the
/// remote peer about the capabilities.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Capa<'a> {
    /// A list of capabilities.
    /// 
    /// See the `Caps` associated constants for possible capabilities.
    ///
    /// - 1   - ChLs channel list.
    /// - 2   - SXSr external source.
    /// - 3   - SXUS per-universe external sources.
    /// - 101 - Art-Net external sources.
    /// - 102 - BSR E1.31 external sources.
    /// - 103 - ETC Net2 external sources.
    /// - 104 - MA-Net external sources.
    pub capabilities: Cow<'a, [u16]>,
}

/// ## SDMX / UNam - Universe Name message.
///
/// The universe name message can be sent by a DMX transmitting peer in order to provide the other
/// end with a displayable name of a universe.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct UNam {
    /// `0`-based index of the universe.
    pub universe_index: u8,
    /// Name of the universe.
    pub universe_name: CString,
}

/// ## SDMX / EnId - Encryption identifier message.
///
/// The EncryptionIdentifier messages is used to agree on encryption schemes when transferring DMX
/// channels. The usage of this message depends completely on the peers communicating it; the
/// contents and results of this message is not part of the CITP specification - it must be agreed
/// upon a priori.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct EnId {
    /// Encryption scheme identifier.
    pub identifier: CString,
}

/// ## SDMX / ChBk - Channel Block message.
///
/// The Channel Block message transmits raw DMX levels to the recipient. How to handle Blind DMX
/// levels is up to the recipient, but the recommended procedure for a visualiser is to switch over
/// to blind DMX whenever such is present and to revert back after some short timeout when it is no
/// longer transmitted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct ChBk<'a> {
    /// Set to `1` for blind preview dmx, `0` otherwise.
    pub blind: u8,
    /// `0`-based index of the universe.
    pub universe_index: u8,
    /// `0` based index of first channel in the universe.
    pub first_channel: u16,
    /// Raw channel levels.
    pub channel_levels: Cow<'a, [u8]>,
}

/// ## SDMX / ChLs - Channel List message
///
/// The Channel List message transmits a set of non-consecutive DMX levels. This message should
/// only be sent if the remote peer has acknowledged supporting it in a Capabilities message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct ChLs<'a> {
    /// The list of channel levels.
    pub channel_levels: Cow<'a, [ChannelLevel]>,
}

/// A single channel level within a list specified via a `ChLs` message.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct ChannelLevel {
    /// `0`-based index of the universe.
    universe_index: u8,
    /// `0`-based index of the channel in the universe.
    channel: u16,
    /// DMX channel level.
    channel_level: u8,
}

/// ## SDMX / SXSr - Set External Source message.
///
/// The Set External Source message can be sent as an alternative to sending `ChBk` messages when
/// DMX can be received over another protocol. In the event of handling multiple universes, the
/// external source specified should be treated as the base universe of a consecutive series of
/// universes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SXSr {
    /// DMX-source connction string.
    ///
    /// The following connection strings are currently defined:
    ///
    /// - **Art-Net**: "ArtNet/<net>/<universe>/<channel>", ie. "ArtNet/0/0/1" is the first channel
    ///   of the first universe on the first network.
    /// - **BSR E1.31 / sACN**: "BSRE1.31/<universe>/<channel>", ie. "BSRE1.31/1/1" is the first
    ///   channel of the first universe.
    /// - **ETC Net2**: "EtcNet2/<channel>", ie. "ETCNet2/1" is the first ETCNet2 channel.
    /// - **MA-Net**: "MANet/<type>/<universe>/<channel>", ie. "MANet/2/0/1" is the first channel
    /// of the first MA-Net 2 universe.
    pub connection_string: CString,
}

/// ## SDMX/SXUS - Set External Universe Source message.
///
/// The Set External Universe Source message functions like the Set External Source mssage, but on
/// a universe level rather than a global level.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Sxus {
    /// `0`-based index of the universe.
    pub universe_index: u8,
    /// DMX-source connection string - as the SXSr message.
    pub connection_string: CString,
}

impl Header {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"SDMX";
}

impl<'a> Capa<'a> {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"Capa";

    pub const CHANNEL_LIST: u16 = 1;
    pub const EXTERNAL_SOURCE: u16 = 2;
    pub const PER_UNIVERSE_EXTERNAL_SOURCES: u16 = 3;
    pub const ART_NET_EXTERNAL_SOURCES: u16 = 101;
    pub const BSR_E131_EXTERNAL_SOURCES: u16 = 102;
    pub const ETC_NET2_EXTERNAL_SOURCES: u16 = 103;
    pub const MA_NET_EXTERNAL_SOURCES: u16 = 103;
}

impl UNam {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"UNam";
}

impl EnId {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"EnId";
}

impl<'a> ChBk<'a> {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"ChBk";
}

impl<'a> ChLs<'a> {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"ChLs";
}

impl SXSr {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"SXSr";
}

impl Sxus {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"SXUS";
}

impl WriteToBytes for Header {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(&self.citp_header)?;
        writer.write_u32::<LE>(self.content_type)?;
        Ok(())
    }
}

impl<T> WriteToBytes for Message<T>
where
    T: WriteToBytes,
{
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(&self.sdmx_header)?;
        writer.write_bytes(&self.message)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for Capa<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        if self.capabilities.len() > std::u16::MAX as usize {
            let err_msg = "the number of capabilities exceeds the maximum possible `u16` value";
            return Err(io::Error::new(io::ErrorKind::InvalidData, err_msg));
        }
        writer.write_u16::<LE>(self.capabilities.len() as u16)?;
        for &cap in self.capabilities.iter() {
            writer.write_u16::<LE>(cap)?;
        }
        Ok(())
    }
}

impl WriteToBytes for UNam {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.universe_index)?;
        writer.write_bytes(&self.universe_name)?;
        Ok(())
    }
}

impl WriteToBytes for EnId {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(&self.identifier)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for ChBk<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.blind)?;
        writer.write_u8(self.universe_index)?;
        writer.write_u16::<LE>(self.first_channel)?;
        writer.write_u16::<LE>(self.channel_levels.len() as _)?;
        for &lvl in self.channel_levels.iter() {
            writer.write_u8(lvl)?;
        }
        Ok(())
    }
}

impl WriteToBytes for ChannelLevel {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.universe_index)?;
        writer.write_u16::<LE>(self.channel)?;
        writer.write_u8(self.channel_level)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for ChLs<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.channel_levels.len() as _)?;
        for ch in self.channel_levels.iter() {
            writer.write_bytes(ch)?;
        }
        Ok(())
    }
}

impl WriteToBytes for SXSr {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(&self.connection_string)?;
        Ok(())
    }
}

impl WriteToBytes for Sxus {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.universe_index)?;
        writer.write_bytes(&self.connection_string)?;
        Ok(())
    }
}

impl ReadFromBytes for Capa<'static> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let capability_count: u16 = reader.read_bytes()?;
        let capabilities = protocol::read_new_vec(reader, capability_count as _)?;
        let capabilities = Capa { capabilities: Cow::Owned(capabilities) };
        Ok(capabilities)
    }
}

impl ReadFromBytes for UNam {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let universe_index = reader.read_u8()?;
        let universe_name = reader.read_bytes()?;
        let unam = UNam { universe_index, universe_name };
        Ok(unam)
    }
}

impl ReadFromBytes for EnId {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let identifier = reader.read_bytes()?;
        let enid = EnId { identifier };
        Ok(enid)
    }
}

impl ReadFromBytes for ChBk<'static> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let blind = reader.read_u8()?;
        let universe_index = reader.read_u8()?;
        let first_channel = reader.read_u16::<LE>()?;
        let channel_level_count: u16 = reader.read_u16::<LE>()?;
        let channel_levels = protocol::read_new_vec(reader, channel_level_count as _)?;
        let channel_levels = Cow::Owned(channel_levels);
        let chbk = ChBk {
            blind,
            universe_index,
            first_channel,
            channel_levels,
        };
        Ok(chbk)
    }
}

impl ReadFromBytes for ChannelLevel {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let universe_index = reader.read_u8()?;
        let channel = reader.read_u16::<LE>()?;
        let channel_level = reader.read_u8()?;
        let ch = ChannelLevel { universe_index, channel, channel_level };
        Ok(ch)
    }
}

impl ReadFromBytes for ChLs<'static> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let channel_level_count = reader.read_u16::<LE>()?;
        let channel_levels = protocol::read_new_vec(reader, channel_level_count as _)?;
        let channel_levels = Cow::Owned(channel_levels);
        let chls = ChLs { channel_levels };
        Ok(chls)
    }
}

impl ReadFromBytes for SXSr {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let connection_string = reader.read_bytes()?;
        let sxsr = SXSr { connection_string };
        Ok(sxsr)
    }
}

impl ReadFromBytes for Sxus {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let universe_index = reader.read_u8()?;
        let connection_string = reader.read_bytes()?;
        let sxus = Sxus { universe_index, connection_string };
        Ok(sxus)
    }
}

impl<'a> SizeBytes for Capa<'a> {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u16>()
        + self.capabilities.len() * mem::size_of::<u16>()
    }
}

impl SizeBytes for UNam {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>() + self.universe_name.size_bytes()
    }
}

impl SizeBytes for EnId {
    fn size_bytes(&self) -> usize {
        self.identifier.size_bytes()
    }
}

impl<'a> SizeBytes for ChBk<'a> {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>()
        + mem::size_of::<u8>()
        + mem::size_of::<u16>()
        + mem::size_of::<u16>()
        + self.channel_levels.len() * mem::size_of::<u8>()
    }
}

impl<'a> SizeBytes for ChLs<'a> {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u16>()
        + self.channel_levels.len() * mem::size_of::<ChannelLevel>()
    }
}

impl SizeBytes for SXSr {
    fn size_bytes(&self) -> usize {
        self.connection_string.size_bytes()
    }
}

impl SizeBytes for Sxus {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>() + self.connection_string.size_bytes()
    }
}
