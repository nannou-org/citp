use crate::protocol;
use std::borrow::Cow;

/// The MSEX layer provides a standard, single, header used at the start of all MSEX packets.
///
/// The `content_type` field identifies the specific MSEX message type (e.g. "GETh" for Get Element
/// Thumbnail, etc). If an implementation receives a message with an unrecognised cookie it must
/// silently discard the message and not treat this as an error condiion. This is to allow the
/// specification to continue to evolve over time.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Header {
    /// The CITP header. CITP ContentType is "MSEX".
    pub citp_header: protocol::Header,
    pub version_major: u8,
    pub version_minor: u8,
    /// A cookie defining which MSEX message it is.
    pub content_type: u32,
}

/// Layout of MSEX messages.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Message<T> {
    /// The MSEX header - the base header with the MSEX content type.
    pub msex_header: Header,
    /// The data for the message.
    pub message: T,
}

/// ## MSEX / CINF - Client Information message
///
/// The Client Information message advises the media server of which versions of MSEX are supported
/// by the client. This message is mandatory and must be sent by the client to the media server
/// immediately after establishing a connection. The media server will examine the list of
/// supported versions and establish the Highest Common MSEX version defined above.
///
/// **Note**: The format of this message up to FutureMessageData cannot be changed in future
/// versions of MSEX, since the client does not y et know which versions te media server will
/// understand. Future versions can be defined however, but they must preserve the format of the
/// previous version and only insert new fields immediately before the FutureMessageData field.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct CInf<'a> {
    /// Number of following MSEX version pairs.
    pub supported_msex_versions_count: u8,
    /// Each 2 byte value is MSB = major MSEX version, LSB = minor MSEX version.
    pub supported_msex_versions: Cow<'a, [[u8; 2]]>,
    /// A hint that future versions of this message may contain trailing data.
    pub future_message_data: Cow<'a, [u8]>,
}

