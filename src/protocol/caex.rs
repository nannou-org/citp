use crate::protocol::{
    self, ReadBytesExt, ReadFromBytes, SizeBytes, Ucs2, WriteBytes, WriteBytesExt, WriteToBytes, LE,
};
use std::{borrow::Cow, io, mem};

/// The CAEX layer provides a standard, single, header used at the start of all CAEX packets.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Header {
    /// The CITP header. CITP ContentType is "CAEX".
    pub citp_header: protocol::Header,
    /// A cookie defining which CAEX message it is.
    pub content_type: u32,
}

/// This message must be sent by Capture or a peer in response to any unknown message or any request that prompts a reply
/// which cannot be served. The CITP header RequestIndex and InResponseTo fields must be honoured when sending this
/// message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Nack {
    pub reason: NackReason,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NackReason {
    UnknownRequest = 0x00,
    IncorrectRequest = 0x01,
    InternalError = 0x02,
    RequestRefused = 0x03,
}

impl From<u8> for NackReason {
    fn from(orig: u8) -> Self {
        match orig {
            0x00 => NackReason::UnknownRequest,
            0x01 => NackReason::IncorrectRequest,
            0x02 => NackReason::InternalError,
            0x03 => NackReason::RequestRefused,
            _ => unreachable!(),
        }
    }
}

impl From<NackReason> for u8 {
    fn from(value: NackReason) -> Self {
        match value {
            NackReason::UnknownRequest => 0x00,
            NackReason::IncorrectRequest => 0x01,
            NackReason::InternalError => 0x02,
            NackReason::RequestRefused => 0x03,
        }
    }
}

/// Layout of CAEX messages.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Message<T> {
    /// The CAEX header - the base header with the CAEX content type.
    pub caex_header: Header,
    /// The data for the message.
    pub message: T,
}

/// ## CAEX / Live View Messages.
///
/// Capture allows a peer to interact with one of its views in live mode. If no view is in live mode, these features will
/// not be available. If multiple views are in live mode, the first view in live mode will be the one with which the peer
/// can interact.

/// This message is sent to Capture as a request for a LiveViewStatus reply.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct GetLiveViewStatus {}

/// This message is sent by Capture in reply to a GetLiveViewStatus message.
#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct LiveViewStatus {
    /// 0x00 = Not available.
    /// 0x01 = Alpha view available.
    /// 0x02 = Beta view available.
    /// 0x03 = Gamma view available.
    pub availability: u8,
    /// The width and height of the view.
    pub size: (u16, u16),
    /// The XYZ position of the camera.
    pub camera_position: [f32; 3],
    /// The XYZ focus of the camera.
    pub camera_focus: [f32; 3],
}

/// This message is sent to Capture as a request for a LiveViewImage reply.
#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct GetLiveViewImage {
    /// 0x01 = JPEG
    pub format: u8,
    /// The width and height requested.
    pub resolution: (u16, u16),
    /// The position of the camera, as XYZ.
    pub camera_position: [f32; 3],
    /// The focus of the camera, as XYZ.
    pub camera_focus: [f32; 3],
}

/// This message is sent by Capture in reply to a GetLiveViewImage message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct LiveViewImage<'a> {
    /// 0x01 = JPEG
    pub format: u8,
    /// The number of bytes in the following field.
    pub data_size: u32,
    /// Image data.
    pub data: Cow<'a, [u8]>,
}

impl GetLiveViewStatus {
    pub const CONTENT_TYPE: u32 = 0x00000100;
}

impl LiveViewStatus {
    pub const CONTENT_TYPE: u32 = 0x00000101;
}

impl GetLiveViewImage {
    pub const CONTENT_TYPE: u32 = 0x00000200;
}

impl LiveViewImage<'_> {
    pub const CONTENT_TYPE: u32 = 0x00000201;
}

/// ## CAEX / Show Synchronization Messages.
///
/// The Show Synchronization messages allow a peer to exchange patch, selection and fixture status information with Capture.
///
/// In order for the user experience to be smooth and seamless, it is necessary to communicate "show state"
/// information with Capture. The following are the rules of interaction:
/// - Capture will send EnterShow and LeaveShow messages as projects are opened and
///   closed, given that the user has enabled the "console link" with the peer. If "console link" is
///   disabled and then reenabled, Capture will act as if the project was closed and opened
///   again. Always keep track of whether Capture is currently in a show or not.
/// - When opening or creating a new show: send an EnterShow message to Capture.
/// - When opening or creating a new show and Capture is currently in a show: send a patch
///   information request to Capture.
/// - When closing a show: send a LeaveShow message to Capture.
/// - When in a show and Capture enters a show: send a patch information request to
///   Capture.
/// - If the user chooses to disable synchronization: act as if the user had closed the show.
/// - If the user chooses to reenable synchronization: act as if the user had just opened the
///   current show.
///
/// It is important that the peer, upon receving complete patch information when both the peer and Capture have
/// entered a show, provides the user with the means to determine whether the patch is in sync and/or requires
/// modification, as well as the option to disable the synchronization

/// This message is sent unsolicited by both Capture and the peer when a show/project is opened and/or the user
/// wishes to enable show synchronization
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct EnterShow {
    /// The name of the show.
    pub name: Ucs2,
}

/// This message is sent unsolicited by both Capture and the peer when a show/project is closed or when the user
/// wishes to disable show synchronization.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct LeaveShow {}

/// This message is sent unsolicited by the peer to Capture in order to choose which transformation space to use for
/// fixtures. The Native transformation space was the only available until this message was introduced and is the one
/// used by Capture. The PanHome transformation attempts to orient moving heads so that they tilt away from and
/// towards the audience. This may fail for fixtures with multiple axis or unconventional constructions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SetFixtureTransformationSpace {
    pub transformation_space: u8,
}

/// This message can be sent unsolicited by Capture or a peer in order to acquire the full patch list from the other side. The
/// expected response is a FixtureList message with Type = 0x00.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureListRequest {}

/// This message is sent in response to a FixtureListRequest message (with Type = 0x00) as well as unsolicited by both Capture
/// and the peer (with Type = 0x01 or Type = 0x02). An existing patch fixture list (Type = 0x00) must contain all known fixtures while
/// a new fixture (Type = 0x01) or exchanged fixture (Type = 0x02) message contains only the fixture(s) that were recently added or
/// exchanged for other fixtures.
#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct FixtureList<'a> {
    pub message_type: FixtureListMessageType,
    /// The number of fixtures following
    pub fixture_count: u16,
    /// The array of fixtures in the message
    pub fixtures: Cow<'a, [Fixture<'a>]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FixtureListMessageType {
    ExistingPatchList = 0x00,
    NewFixture = 0x01,
    ExchangeFixture = 0x02,
}

impl From<u8> for FixtureListMessageType {
    fn from(orig: u8) -> Self {
        match orig {
            0x00 => FixtureListMessageType::ExistingPatchList,
            0x01 => FixtureListMessageType::NewFixture,
            0x02 => FixtureListMessageType::ExchangeFixture,
            _ => unreachable!(),
        }
    }
}

impl From<FixtureListMessageType> for u8 {
    fn from(original: FixtureListMessageType) -> u8 {
        match original {
            FixtureListMessageType::ExistingPatchList => 0x00,
            FixtureListMessageType::NewFixture => 0x01,
            FixtureListMessageType::ExchangeFixture => 0x02,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IdentifierType {
    RDMDeviceModelId = 0x00, // u16
    /// (Note: The RDMPersonalityId IdentifierType is incorrectly uint64 when it should have been uint16. As a result of this, the highest six bytes should be set to zero)
    RDMPersonalityId = 0x01, // u64
    AtlaBaseFixtureId = 0x02, // guid
    AtlaBaseModeId = 0x03,   // guid
    CaptureInstanceId = 0x04, // guid
    RDMManufacturerId = 0x05, // u16
}

impl From<u8> for IdentifierType {
    fn from(orig: u8) -> Self {
        match orig {
            0x00 => IdentifierType::RDMDeviceModelId,
            0x01 => IdentifierType::RDMPersonalityId,
            0x02 => IdentifierType::AtlaBaseFixtureId,
            0x03 => IdentifierType::AtlaBaseModeId,
            0x04 => IdentifierType::CaptureInstanceId,
            0x05 => IdentifierType::RDMManufacturerId,
            _ => unreachable!(),
        }
    }
}

impl From<IdentifierType> for u8 {
    fn from(original: IdentifierType) -> u8 {
        match original {
            IdentifierType::RDMDeviceModelId => 0x00,
            IdentifierType::RDMPersonalityId => 0x01,
            IdentifierType::AtlaBaseFixtureId => 0x02,
            IdentifierType::AtlaBaseModeId => 0x03,
            IdentifierType::CaptureInstanceId => 0x04,
            IdentifierType::RDMManufacturerId => 0x05,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Identifier<'a> {
    pub identifier_type: IdentifierType,
    /// The size of the data following.
    pub data_size: u16,
    /// Identifier type specific data.
    pub data: Cow<'a, [u8]>,
}

#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct Fixture<'a> {
    /// Console's fixture identifier.
    /// Set to 0xffffffff if unknown by Capture.
    pub fixture_identifier: u32,
    /// The name of the fixture's manufacturer.
    pub manufacturer_name: Ucs2,
    /// The model name of the fixture.
    pub fixture_name: Ucs2,
    /// The name of DMX mode.
    pub mode_name: Ucs2,
    /// The number of channels of the DMX mode.
    pub channel_count: u16,
    /// A boolean 0x00 or 0x01 indicating whether it's a dimmer (only) fixture or not.
    pub is_dimmer: u8,
    /// The number of following identifier blocks.
    pub identifier_count: u8,
    /// The fixtures identifiers
    pub identifiers: Cow<'a, [Identifier<'a>]>,
    /// The DMX patching and viz position and rotation information
    pub data: FixtureData,
}

#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct FixtureData {
    /// A boolean 0x00 or 0x01 indicating whether the fixture is patched or not.
    pub patched: u8,
    /// The (0-based) universe index.
    pub universe: u8,
    /// The (0-based) DMX channel.
    pub universe_channel: u16,
    /// The unit number.
    pub unit: Ucs2,
    /// The channel number.
    pub channel: u16,
    /// The circuit number.
    pub circuit: Ucs2,
    /// Any notes.
    pub note: Ucs2,
    /// The 3D position
    pub position: [f32; 3],
    /// The 3D angle.
    pub angles: [f32; 3],
}

/// This message can be sent to Capture in order to set the fixture identifier of a fixture based on its instance id (the
/// 0x04 identifier type of the FixtureList message). This is only required in the specific scenario of a fixture being
/// added in Capture and then patched on the console. The console can then respond to the addition of the fixture
/// with a FixtureIdentify message before it sends the FixtureModify message (which relies on the identifier having
/// been set).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureIdentify<'a> {
    /// The number of fixture identifications following.
    pub fixture_count: u16,
    /// Array of fixture identifications.
    pub fixture_identifications: Cow<'a, [FixtureIdentification]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureIdentification {
    // The instance id of the fixture.
    pub capture_instance_id: [u8; 16],
    /// The fixture identifier to set.
    pub fixture_identifier: u32,
}

/// This message is sent unsolicited by both Capture and the peer whenever a fixture has been modified. All fields
/// must always be present, but it is important that the ChangedFields field indicates which have actually been modified.
#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct FixtureModify<'a> {
    /// The number of fixtures following.
    pub fixture_count: u16,
    /// Array of fixture modifications.
    pub fixture_modifications: Cow<'a, [FixtureModification]>,
}

#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct FixtureModification {
    // Console's fixture identifier.
    pub fixture_identifier: u32,
    // Bitmask indicating which of the following fields have changed.
    pub changed_fields: u8,
    /// The DMX patching and viz position and rotation information
    pub data: FixtureData,
}

/// This message is sent unsolicited by both Capture and the peer whenever on or more fixture(s) have been removed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureRemove<'a> {
    /// The number of fixture identifiers following.
    pub fixture_count: u16,
    /// Array of fixture identifiers.
    pub fixture_identifiers: Cow<'a, [u32]>,
}

/// This message is sent unsolicited by by both Capture and the peer to inform the other side of a new fixture selection.
/// Note that the order of the fixture identifiers should carry the order in which the fixture(s) were selected.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureSelection<'a> {
    /// The number of fixture identifiers following.
    pub fixture_count: u16,
    /// Array of fixture identifiers.
    pub fixture_identifiers: Cow<'a, [u32]>,
}

/// This message is sent unsolicited by the peer to Capture in order to convey "live information" data that can be displayed by
/// Capture.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureConsoleStatus<'a> {
    /// The number of fixtures following.
    pub fixture_count: u16,
    /// Array of fixtures states.
    pub fixtures_state: Cow<'a, [FixtureState]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureState {
    /// Console's fixture identifier.
    pub fixture_identifier: u32,
    /// The fixture has been locked from manipulation.
    pub locked: u8,
    /// The fixture has a clearable programmer state.
    pub clearable: u8,
}

impl EnterShow {
    pub const CONTENT_TYPE: u32 = 0x00020100;
}

impl LeaveShow {
    pub const CONTENT_TYPE: u32 = 0x00020101;
}

impl SetFixtureTransformationSpace {
    pub const CONTENT_TYPE: u32 = 0x00020150;
}

impl FixtureListRequest {
    pub const CONTENT_TYPE: u32 = 0x00020200;
}

impl<'a> FixtureList<'a> {
    pub const CONTENT_TYPE: u32 = 0x00020201;
}

impl<'a> FixtureIdentify<'a> {
    pub const CONTENT_TYPE: u32 = 0x00020204;
}

impl<'a> FixtureModify<'a> {
    pub const CONTENT_TYPE: u32 = 0x00020202;
}

impl<'a> FixtureRemove<'a> {
    pub const CONTENT_TYPE: u32 = 0x00020203;
}

impl<'a> FixtureSelection<'a> {
    pub const CONTENT_TYPE: u32 = 0x00020300;
}

impl<'a> FixtureConsoleStatus<'a> {
    pub const CONTENT_TYPE: u32 = 0x00020400;
}

/// ## CAEX / Laser Feed Messages.
///
/// A peer may serve laser feeds to Capture. Information to Capture about which feeds are available and information
/// from Capture about which feeds to transmit is sent over the TCP based CITP session. Actual feed frame data is
/// transmitted to the UDP based CITP multicast address.
/// In order for Capture to be able to correlate the feed frames with the appropriate session, a process instance
/// unique and random "source key" is to be generated by the laser controller

/// This message is sent by Capture upon connection to determine what laser feeds are available. Receving this
/// message is an indication of Capture's ability to understand CAEX laser feeds.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct GetLaserFeedList {}

/// This message can be sent to Capture both in response to a GetLaserFeedList message as well as unsolicited if
/// the list of available laser feeds has changed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct LaserFeedList<'a> {
    /// The source key used in frame messages.
    pub source_key: u32,
    /// The number of laser feed listings that follow.
    pub feed_count: u8,
    /// The name of the feed.
    pub feed_names: Cow<'a, [Ucs2]>,
    //pub feed_names: Cow<'a, [CString]>,
}

/// This message is sent by Capture to indicate whether it wishes a laser feed to be transmitted or not. The frame rate
/// can be seen as an indication of the maximum frame rate meaningful to Capture.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct LaserFeedControl {
    /// The 0-based index of the feed.
    pub feed_index: u8,
    /// The frame rate requested, 0 to disable transmission
    pub frame_rate: u8,
}

/// This message is sent unsolicited to Capture, carrying feed frame data.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct LaserFeedFrame<'a> {
    /// The source key as in the LaserFeedList message.
    pub source_key: u32,
    /// The 0-based index of the feed.
    pub feed_index: u8,
    /// A 0-based sequence number for out of order data detection.
    pub frame_sequence: u32,
    /// The number of points that follow.
    pub point_count: u16,
    /// Array of laser points.
    pub points: Cow<'a, [LaserPoint]>,
}

/// Example of how a point in constructed
///
/// Point.X [0, 4093] = Point.XLowByte + (Point.XYHighNibbles & 0x0f) << 8
/// Point.Y [0, 4093] = Point.YLowByte + (Point.XYHighNibbles & 0xf0) << 4
/// Point.R [0, 31] = Point.Color & 0x001f
/// Point.G [0, 63] = (Point.Color & 0x07e0) >> 5
/// Point.B [0, 31] = (Point.Color & 0xf800) >> 11
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct LaserPoint {
    /// The low byte of the x coordinate.
    pub x_low_byte: u8,
    /// The low byte of the y coordinate.
    pub y_low_byte: u8,
    /// The high nibbles of the x and y coordinates.
    pub xy_high_nibbles: u8,
    /// The colour packed as R5 G6 B5.
    pub color: u16,
}

impl Header {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"CAEX";
}

impl Nack {
    pub const CONTENT_TYPE: u32 = 0xFFFFFFFF;
}

impl GetLaserFeedList {
    pub const CONTENT_TYPE: u32 = 0x00030100;
}

impl<'a> LaserFeedList<'a> {
    pub const CONTENT_TYPE: u32 = 0x00030101;
}

impl LaserFeedControl {
    pub const CONTENT_TYPE: u32 = 0x00030102;
}

impl<'a> LaserFeedFrame<'a> {
    pub const CONTENT_TYPE: u32 = 0x00030200;
}

impl WriteToBytes for Header {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(self.citp_header)?;
        writer.write_u32::<LE>(self.content_type)?;
        Ok(())
    }
}

impl WriteToBytes for Nack {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.reason.into())?;
        Ok(())
    }
}

impl<T> WriteToBytes for Message<T>
where
    T: WriteToBytes,
{
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(self.caex_header)?;
        writer.write_bytes(&self.message)?;
        Ok(())
    }
}

impl WriteToBytes for GetLiveViewStatus {
    fn write_to_bytes<W: WriteBytesExt>(&self, _writer: W) -> io::Result<()> {
        Ok(())
    }
}

impl WriteToBytes for LiveViewStatus {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.availability)?;
        writer.write_u16::<LE>(self.size.0)?;
        writer.write_u16::<LE>(self.size.1)?;
        writer.write_f32::<LE>(self.camera_position[0])?;
        writer.write_f32::<LE>(self.camera_position[1])?;
        writer.write_f32::<LE>(self.camera_position[2])?;
        writer.write_f32::<LE>(self.camera_focus[0])?;
        writer.write_f32::<LE>(self.camera_focus[1])?;
        writer.write_f32::<LE>(self.camera_focus[2])?;
        Ok(())
    }
}

impl WriteToBytes for GetLiveViewImage {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.format)?;
        writer.write_u16::<LE>(self.resolution.0)?;
        writer.write_u16::<LE>(self.resolution.1)?;
        writer.write_f32::<LE>(self.camera_position[0])?;
        writer.write_f32::<LE>(self.camera_position[1])?;
        writer.write_f32::<LE>(self.camera_position[2])?;
        writer.write_f32::<LE>(self.camera_focus[0])?;
        writer.write_f32::<LE>(self.camera_focus[1])?;
        writer.write_f32::<LE>(self.camera_focus[2])?;
        Ok(())
    }
}

impl WriteToBytes for LiveViewImage<'_> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.format)?;
        writer.write_u32::<LE>(self.data_size)?;
        writer.write_all(&self.data)?;
        Ok(())
    }
}

impl WriteToBytes for EnterShow {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        self.name.write_to_bytes(&mut writer)?;
        Ok(())
    }
}

impl WriteToBytes for LeaveShow {
    fn write_to_bytes<W: WriteBytesExt>(&self, _writer: W) -> io::Result<()> {
        Ok(())
    }
}

impl WriteToBytes for SetFixtureTransformationSpace {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.transformation_space)?;
        Ok(())
    }
}

impl WriteToBytes for FixtureListRequest {
    fn write_to_bytes<W: WriteBytesExt>(&self, _writer: W) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> WriteToBytes for FixtureList<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.message_type.into())?;
        writer.write_u16::<LE>(self.fixture_count)?;
        for fixture in self.fixtures.iter() {
            fixture.write_to_bytes(&mut writer)?;
        }
        Ok(())
    }
}

impl<'a> WriteToBytes for Fixture<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<LE>(self.fixture_identifier)?;
        self.manufacturer_name.write_to_bytes(&mut writer)?;
        self.fixture_name.write_to_bytes(&mut writer)?;
        self.mode_name.write_to_bytes(&mut writer)?;
        writer.write_u16::<LE>(self.channel_count)?;
        writer.write_u8(self.is_dimmer)?;
        writer.write_u8(self.identifier_count)?;
        for identifier in self.identifiers.iter() {
            identifier.write_to_bytes(&mut writer)?;
        }
        self.data.write_to_bytes(&mut writer)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for Identifier<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.identifier_type.into())?;
        writer.write_u16::<LE>(self.data_size)?;
        writer.write_all(&self.data)?;
        Ok(())
    }
}

impl WriteToBytes for FixtureData {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.patched)?;
        writer.write_u8(self.universe)?;
        writer.write_u16::<LE>(self.universe_channel)?;
        self.unit.write_to_bytes(&mut writer)?;
        writer.write_u16::<LE>(self.channel)?;
        self.circuit.write_to_bytes(&mut writer)?;
        self.note.write_to_bytes(&mut writer)?;
        writer.write_f32::<LE>(self.position[0])?;
        writer.write_f32::<LE>(self.position[1])?;
        writer.write_f32::<LE>(self.position[2])?;
        writer.write_f32::<LE>(self.angles[0])?;
        writer.write_f32::<LE>(self.angles[1])?;
        writer.write_f32::<LE>(self.angles[2])?;
        Ok(())
    }
}

impl<'a> WriteToBytes for FixtureIdentify<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.fixture_count)?;
        for id in self.fixture_identifications.iter() {
            id.write_to_bytes(&mut writer)?;
        }
        Ok(())
    }
}

impl WriteToBytes for FixtureIdentification {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.capture_instance_id)?;
        writer.write_u32::<LE>(self.fixture_identifier)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for FixtureModify<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.fixture_count)?;
        for fix in self.fixture_modifications.iter() {
            fix.write_to_bytes(&mut writer)?;
        }
        Ok(())
    }
}

impl WriteToBytes for FixtureModification {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<LE>(self.fixture_identifier)?;
        writer.write_u8(self.changed_fields)?;
        self.data.write_to_bytes(writer)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for FixtureRemove<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.fixture_count)?;
        for id in self.fixture_identifiers.iter() {
            writer.write_u32::<LE>(*id)?;
        }
        Ok(())
    }
}

impl<'a> WriteToBytes for FixtureSelection<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.fixture_count)?;
        for id in self.fixture_identifiers.iter() {
            writer.write_u32::<LE>(*id)?;
        }
        Ok(())
    }
}

impl<'a> WriteToBytes for FixtureConsoleStatus<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<LE>(self.fixture_count)?;
        for state in self.fixtures_state.iter() {
            state.write_to_bytes(&mut writer)?;
        }
        Ok(())
    }
}

impl WriteToBytes for FixtureState {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<LE>(self.fixture_identifier)?;
        writer.write_u8(self.locked)?;
        writer.write_u8(self.clearable)?;
        Ok(())
    }
}

impl WriteToBytes for GetLaserFeedList {
    fn write_to_bytes<W: WriteBytesExt>(&self, _writer: W) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> WriteToBytes for LaserFeedList<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<LE>(self.source_key)?;
        writer.write_u8(self.feed_names.len() as _)?;
        for name in self.feed_names.iter() {
            name.write_to_bytes(&mut writer)?;
        }
        Ok(())
    }
}

impl WriteToBytes for LaserFeedControl {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.feed_index)?;
        writer.write_u8(self.frame_rate)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for LaserFeedFrame<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<LE>(self.source_key)?;
        writer.write_u8(self.feed_index)?;
        writer.write_u32::<LE>(self.frame_sequence)?;
        writer.write_u16::<LE>(self.points.len() as _)?;
        for p in self.points.iter() {
            p.write_to_bytes(&mut writer)?;
        }
        Ok(())
    }
}

impl WriteToBytes for LaserPoint {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.x_low_byte)?;
        writer.write_u8(self.y_low_byte)?;
        writer.write_u8(self.xy_high_nibbles)?;
        writer.write_u16::<LE>(self.color)?;
        Ok(())
    }
}

impl ReadFromBytes for LaserFeedControl {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let feed_index = reader.read_u8()?;
        let frame_rate = reader.read_u8()?;
        let laser_feed_control = LaserFeedControl {
            feed_index,
            frame_rate,
        };
        Ok(laser_feed_control)
    }
}

impl ReadFromBytes for LiveViewStatus {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let availability = reader.read_u8()?;
        let size_w = reader.read_u16::<LE>()?;
        let size_h = reader.read_u16::<LE>()?;
        let position = [
            reader.read_f32::<LE>()?,
            reader.read_f32::<LE>()?,
            reader.read_f32::<LE>()?,
        ];
        let focus = [
            reader.read_f32::<LE>()?,
            reader.read_f32::<LE>()?,
            reader.read_f32::<LE>()?,
        ];
        Ok(LiveViewStatus {
            availability,
            size: (
                size_w,
                size_h
            ),
            camera_position: position,
            camera_focus: focus,
        })
    }
}

impl ReadFromBytes for GetLiveViewImage {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let format = reader.read_u8()?;
        let res_w = reader.read_u16::<LE>()?;
        let res_h = reader.read_u16::<LE>()?;
        let position = [
            reader.read_f32::<LE>()?,
            reader.read_f32::<LE>()?,
            reader.read_f32::<LE>()?,
        ];
        let focus = [
            reader.read_f32::<LE>()?,
            reader.read_f32::<LE>()?,
            reader.read_f32::<LE>()?,
        ];
        Ok(GetLiveViewImage {
            format,
            resolution: (
                res_w,
                res_h
            ),
            camera_position: position,
            camera_focus: focus,
        })
    }
}

impl ReadFromBytes for LiveViewImage<'_> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let format = reader.read_u8()?;
        let data_size = reader.read_u32::<LE>()?;
        let mut data = vec![0u8; data_size as usize];
        reader.read_exact(&mut data)?;
        Ok(LiveViewImage {
            format,
            data_size,
            data: Cow::Owned(data),
        })
    }
}

impl ReadFromBytes for EnterShow {
    fn read_from_bytes<R: ReadBytesExt>(reader: R) -> io::Result<Self> {
        let name = Ucs2::read_from_bytes(reader)?;
        Ok(EnterShow { name })
    }
}

impl ReadFromBytes for SetFixtureTransformationSpace {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let transformation_space = reader.read_u8()?;
        Ok(SetFixtureTransformationSpace {
            transformation_space,
        })
    }
}

impl<'a> ReadFromBytes for FixtureList<'a> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let message_type: FixtureListMessageType = reader.read_u8()?.into();
        let fixture_count = reader.read_u16::<LE>()?;
        let mut fixtures = Vec::new();
        for _ in 0..fixture_count {
            let fixture_identifier = reader.read_u32::<LE>()?;
            let manufacturer_name = Ucs2::read_from_bytes(&mut reader)?;
            let fixture_name = Ucs2::read_from_bytes(&mut reader)?;
            let mode_name = Ucs2::read_from_bytes(&mut reader)?;
            let channel_count = reader.read_u16::<LE>()?;
            let is_dimmer = reader.read_u8()?;
            let identifier_count = reader.read_u8()?;
            let mut identifiers = Vec::new();
            for _ in 0..identifier_count {
                identifiers.push(Identifier::read_from_bytes(&mut reader)?);
            }
            let data = FixtureData::read_from_bytes(&mut reader)?;

            fixtures.push(Fixture {
                fixture_identifier,
                manufacturer_name,
                fixture_name,
                mode_name,
                channel_count,
                is_dimmer,
                identifier_count,
                identifiers: Cow::Owned(identifiers),
                data,
            })
        }

        Ok(FixtureList {
            message_type,
            fixture_count,
            fixtures: Cow::Owned(fixtures),
        })
    }
}

impl<'a> ReadFromBytes for Identifier<'a> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let identifier_type: IdentifierType = reader.read_u8()?.into();
        let data_size = reader.read_u16::<LE>()?;
        let mut data = vec![0u8; data_size.into()];
        reader.read_exact(&mut data)?;
        Ok(Identifier {
            identifier_type,
            data_size,
            data: Cow::Owned(data),
        })
    }
}

impl ReadFromBytes for FixtureData {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        Ok(FixtureData {
            patched: reader.read_u8()?,
            universe: reader.read_u8()?,
            universe_channel: reader.read_u16::<LE>()?,
            unit: Ucs2::read_from_bytes(&mut reader)?,
            channel: reader.read_u16::<LE>()?,
            circuit: Ucs2::read_from_bytes(&mut reader)?,
            note: Ucs2::read_from_bytes(&mut reader)?,
            position: [
                reader.read_f32::<LE>()?,
                reader.read_f32::<LE>()?,
                reader.read_f32::<LE>()?,
            ],
            angles: [
                reader.read_f32::<LE>()?,
                reader.read_f32::<LE>()?,
                reader.read_f32::<LE>()?,
            ],
        })
    }
}

impl<'a> ReadFromBytes for FixtureIdentify<'a> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let fixture_count = reader.read_u16::<LE>()?;
        let mut fixture_identifications = Vec::with_capacity(fixture_count as usize);
        for _ in 0..fixture_count {
            let mut capture_instance_id = [0u8; 16];
            reader.read_exact(&mut capture_instance_id)?;
            let fixture_identifier = reader.read_u32::<LE>()?;
            fixture_identifications.push(FixtureIdentification {
                capture_instance_id,
                fixture_identifier,
            });
        }
        Ok(FixtureIdentify {
            fixture_count,
            fixture_identifications: Cow::Owned(fixture_identifications),
        })
    }
}

impl<'a> ReadFromBytes for FixtureModify<'a> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let fixture_count = reader.read_u16::<LE>()?;
        let mut fixture_modifications = Vec::with_capacity(fixture_count as usize);
        for _ in 0..fixture_count {
            let fixture_identifier = reader.read_u32::<LE>()?;
            let changed_fields = reader.read_u8()?;
            let data = FixtureData::read_from_bytes(&mut reader)?;
            fixture_modifications.push(FixtureModification {
                fixture_identifier,
                changed_fields,
                data,
            });
        }
        Ok(FixtureModify {
            fixture_count,
            fixture_modifications: Cow::Owned(fixture_modifications),
        })
    }
}

impl<'a> ReadFromBytes for FixtureRemove<'a> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let fixture_count = reader.read_u16::<LE>()?;
        let mut fixture_identifiers = Vec::new();
        for _ in 0..fixture_count {
            fixture_identifiers.push(reader.read_u32::<LE>()?);
        }
        Ok(FixtureRemove {
            fixture_count,
            fixture_identifiers: Cow::Owned(fixture_identifiers),
        })
    }
}

impl<'a> ReadFromBytes for FixtureSelection<'a> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let fixture_count = reader.read_u16::<LE>()?;
        let mut fixture_identifiers = Vec::with_capacity(fixture_count as usize);
        for _ in 0..fixture_count {
            fixture_identifiers.push(reader.read_u32::<LE>()?);
        }
        Ok(FixtureSelection {
            fixture_count,
            fixture_identifiers: Cow::Owned(fixture_identifiers),
        })
    }
}

impl<'a> ReadFromBytes for FixtureConsoleStatus<'a> {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let fixture_count = reader.read_u16::<LE>()?;
        let mut fixtures_state = Vec::with_capacity(fixture_count as usize);
        for _ in 0..fixture_count {
            let fixture_identifier = reader.read_u32::<LE>()?;
            let locked = reader.read_u8()?;
            let clearable = reader.read_u8()?;
            fixtures_state.push(FixtureState {
                fixture_identifier,
                locked,
                clearable,
            });
        }
        Ok(FixtureConsoleStatus {
            fixture_count,
            fixtures_state: Cow::Owned(fixtures_state),
        })
    }
}

impl SizeBytes for LiveViewStatus {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>()
            + (mem::size_of::<u16>() * 2)
            + (mem::size_of::<f32>() * 3)
            + (mem::size_of::<f32>() * 3)
    }
}

impl SizeBytes for GetLiveViewImage {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>()
            + (mem::size_of::<u16>() * 2)
            + (mem::size_of::<f32>() * 3)
            + (mem::size_of::<f32>() * 3)
    }
}

impl SizeBytes for LiveViewImage<'_> {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>()
            + mem::size_of::<u32>()
            + self.data.len()
    }
}

impl SizeBytes for EnterShow {
    fn size_bytes(&self) -> usize {
        self.name.size_bytes()
    }
}

impl SizeBytes for SetFixtureTransformationSpace {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>()
    }
}

impl<'a> SizeBytes for FixtureList<'a> {
    fn size_bytes(&self) -> usize {
        let mut fixtures_size = 0;
        for fixture in self.fixtures.iter() {
            fixtures_size += fixture.size_bytes();
        }
        mem::size_of::<u8>() + mem::size_of::<u16>() + fixtures_size
    }
}

impl<'a> SizeBytes for Identifier<'a> {
    fn size_bytes(&self) -> usize {
        let mut data_size = 0;
        for _ in self.data.iter() {
            data_size += mem::size_of::<u8>();
        }
        mem::size_of::<u8>() + mem::size_of::<u16>() + data_size
    }
}

impl<'a> SizeBytes for Fixture<'a> {
    fn size_bytes(&self) -> usize {
        let mut identifiers_size = 0;
        for identifier in self.identifiers.iter() {
            identifiers_size += identifier.size_bytes();
        }

        mem::size_of::<u32>()
            + self.manufacturer_name.size_bytes()
            + self.fixture_name.size_bytes()
            + self.mode_name.size_bytes()
            + mem::size_of::<u16>()
            + mem::size_of::<u8>()
            + mem::size_of::<u8>()
            + identifiers_size
            + self.data.size_bytes()
    }
}

impl SizeBytes for FixtureData {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>()
            + mem::size_of::<u8>()
            + mem::size_of::<u16>()
            + self.unit.size_bytes()
            + mem::size_of::<u16>()
            + self.circuit.size_bytes()
            + self.note.size_bytes()
            + (mem::size_of::<f32>() * 3)
            + (mem::size_of::<f32>() * 3)
    }
}

impl<'a> SizeBytes for FixtureIdentify<'a> {
    fn size_bytes(&self) -> usize {
        let fixture_ident_size
            = mem::size_of::<[u8; 16]>()
            + mem::size_of::<u32>();

        mem::size_of::<u16>()
            + (fixture_ident_size * self.fixture_identifications.len())
    }
}

impl<'a> SizeBytes for FixtureModify<'a> {
    fn size_bytes(&self) -> usize {
        let mut fixture_mods_size = 0;
        for fix in self.fixture_modifications.iter() {
            fixture_mods_size += fix.size_bytes();
        }

        mem::size_of::<u16>() + fixture_mods_size
    }
}

impl SizeBytes for FixtureModification {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u32>()
            + mem::size_of::<u8>()
            + self.data.size_bytes()
    }
}

impl<'a> SizeBytes for FixtureRemove<'a> {
    fn size_bytes(&self) -> usize {
        let mut fixture_ids_size = 0;
        for _ in 0..self.fixture_count {
            fixture_ids_size += mem::size_of::<u32>();
        }

        mem::size_of::<u16>() + fixture_ids_size
    }
}

impl<'a> SizeBytes for FixtureSelection<'a> {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u16>()
            + (mem::size_of::<u32>() * self.fixture_identifiers.len())
    }
}

impl<'a> SizeBytes for FixtureConsoleStatus<'a> {
    fn size_bytes(&self) -> usize {
        let fixture_state_len
            = mem::size_of::<u32>()
            + mem::size_of::<u8>()
            + mem::size_of::<u8>();
        mem::size_of::<u16>()
            + (fixture_state_len * self.fixtures_state.len())
    }
}

impl<'a> SizeBytes for LaserFeedList<'a> {
    fn size_bytes(&self) -> usize {
        let mut feed_names_size = 0;
        for name in self.feed_names.iter() {
            feed_names_size += name.size_bytes();
        }
        mem::size_of::<u32>() + mem::size_of::<u8>() + feed_names_size
    }
}

impl SizeBytes for LaserFeedControl {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>() + mem::size_of::<u8>()
    }
}

impl<'a> SizeBytes for LaserFeedFrame<'a> {
    fn size_bytes(&self) -> usize {
        let mut ps = 0;
        for p in self.points.iter() {
            ps += p.size_bytes();
        }
        mem::size_of::<u32>()
            + mem::size_of::<u8>()
            + mem::size_of::<u32>()
            + mem::size_of::<u16>()
            + ps
    }
}

impl SizeBytes for LaserPoint {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>() + mem::size_of::<u8>() + mem::size_of::<u8>() + mem::size_of::<u16>()
    }
}
