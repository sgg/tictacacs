use std::convert::TryFrom;

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian, ReadBytesExt};
use log::*;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use md5::Digest;

pub const TACACS_VERSION: u8 = 0xc0;

/// The type of TACACS+ packet
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-4.1-10
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum Type {
    /// TAC_PLUS_AUTHEN
    Authentication = 0x01,
    /// TAC_PLUS_AUTHOR
    Authorization = 0x02,
    /// TAC_PLUS_ACCT
    Accounting = 0x03,
}

impl TryFrom<u8> for Type {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        todo!()
    }
}

bitflags! {
    /// Configuration flags
    ///
    /// https://www.rfc-editor.org/rfc/rfc8907.html#section-4.1-14
    pub struct Flags: u8 {
        /// TAC_PLUS_UNENCRYPTED
        ///
        /// This flag indicates that the sender did not obfuscate the body of the packet.
        const UNENCRYPTED = 0x01;
        /// TAC_PLUS_SINGLE_CONNECT_FLAG
        ///
        /// Used to allow a client and server to negotiate "Single Connection Mode
        const SINGLE_CONNECT_FLAG = 0x04;
    }
}

/// A TACACS+ Packet Header
///
/// A 12-byte structure describing the remainder of the TACACS packet.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-4.1
#[derive(Clone, Copy, Debug)]
pub struct Header {
    /// The TACACS+ version number
    pub version: u8,
    /// The type of TACACS+ packet
    pub packet_type: Type,
    /// This is the sequence number of the current packet.
    ///
    /// The first packet in a session MUST have the sequence number 1,
    /// and each subsequent packet will increment the sequence number by one.
    /// TACACS+ clients only send packets containing odd sequence numbers,
    /// and TACACS+ servers only send packets containing even sequence numbers.
    ///
    /// The sequence number must never wrap, i.e., if the sequence number 28-1 is ever reached,
    /// that session must terminate and be restarted with a sequence number of 1.
    pub seq_no: u8,
    pub flags: Flags,
    /// The ID for this TACACS+ session. This field does not change for the duration of the TACACS+ session.
    pub session_id: u32,
    /// The total length of the body associated with this header.
    pub length: u32,
}

impl Header {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(
            bytes.len() >= 12,
            "TACACS+ header must be at least {} bytes",
            bytes.len()
        );
        let header = &bytes[..12];
        Self {
            version: header[0],
            packet_type: Type::from_u8(header[1]).expect("Failed to parse packet type"),
            seq_no: header[2],
            flags: Flags::from_bits(header[3]).expect("Failed to parse flags"),
            session_id: NetworkEndian::read_u32(&header[4..8]),
            length: NetworkEndian::read_u32(&header[8..12]),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);

        buf.push(self.version);
        buf.push(self.packet_type.to_u8().unwrap());
        buf.push(self.seq_no);
        buf.push(self.flags.bits());
        buf.extend_from_slice(self.session_id.to_be_bytes().as_ref());
        buf.extend_from_slice(self.length.to_be_bytes().as_ref());

        buf
    }

    pub fn major_version(&self) -> u8 {
        (self.version & 0xf0) >> 4
    }

    pub fn minor_version(&self) -> u8 {
        self.version & 0x0f
    }

    /// Calculate the initial pad used for data obfuscation
    ///
    /// https://www.rfc-editor.org/rfc/rfc8907.html#name-data-obfuscation
    pub fn initial_pad(&self, secret: &str) -> [u8; 16] {
        let mut hasher = md5::Md5::new();
        // MD5_1 = MD5{session_id, key, version, seq_no}
        hasher.update(self.session_id.to_be_bytes()); // the session id must be provided in network byte order
        hasher.update(secret.as_bytes());
        hasher.update([self.version]);
        hasher.update([self.seq_no]);
        hasher.finalize().into()
    }

    fn subsequent_pad(&self, prev_hash: &[u8], secret: &str) -> [u8; 16] {
        let mut hasher = md5::Md5::new();
        hasher.update(self.session_id.to_be_bytes());
        hasher.update(secret.as_bytes());
        hasher.update([self.version]);
        hasher.update([self.seq_no]);
        hasher.update(prev_hash);

        hasher.finalize().into()
    }

    /// Calculate the psuedo_pad used to de-obfuscate the data associated with this packet.
    pub fn psuedo_pad(&self, secret: &str) -> Vec<u8> {
        let mut final_pad = Vec::with_capacity(self.length as _);
        let mut pad = self.initial_pad(secret);
        final_pad.extend_from_slice(&pad);

        while final_pad.len() < self.length as _ {
            pad = self.subsequent_pad(&pad, secret);
            final_pad.extend_from_slice(&pad)
        }

        final_pad.truncate(self.length as _);
        final_pad
    }
}

/// The packet body for an Authentication START request
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-5.1-3
#[derive(Clone, Debug)]
pub struct AuthenStart {
    pub action: AuthenAction,
    /// The privilege level that the user is authenticating as.
    pub priv_lvl: u8,
    pub authen_type: AuthenType,
    /// The service that is requesting authentication.
    pub authen_service: AuthenService,
    pub user: Option<String>,
    pub port: String,
    pub rem_addr: Option<String>,
    pub data: String,
}

impl AuthenStart {
    /// Create a packet from the body of a TACACS+ request.
    ///
    /// An optional pad may be provided if "encryption" is enabled.
    pub fn from_bytes(bytes: &[u8], pad: Option<&[u8]>) -> Self {
        let decode = |index: u8| {
            let index = index as usize;
            if let Some(pad) = pad {
                bytes[index] ^ pad[index]
            } else {
                bytes[index]
            }
        };

        let decode_str = |start: u8, length: u8| {
            let start = (start + 8); // skip the first 8 bytes of the packet as they are fixed
            let end = start + length;

            (start..end)
                .map(|idx| decode(idx) as char)
                .collect::<String>()
        };

        let action = AuthenAction::from_u8(decode(0)).expect("Failed to parse action");
        let priv_lvl = decode(1);
        let authen_type = AuthenType::from_u8(decode(2)).expect("failed to parse type");
        let authen_service = AuthenService::from_u8(decode(3)).expect("failed to parse service");
        let (user_len, port_len, rem_addr_len, data_len) = (decode(4), decode(5), decode(6), decode(7));

        let user = match user_len {
            0 => None,
            _ => Some(decode_str(0, user_len)),
        };
        let port = decode_str(user_len, port_len);

        let rem_addr = match rem_addr_len {
            0 => None,
            _ => Some(decode_str(user_len + port_len, rem_addr_len)),
        };

        let data = decode_str(user_len + port_len + rem_addr_len, data_len);

        Self {
            action,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_addr,
            data,
        }
    }
}

/// The action of an authentication request.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-5.1-3
#[repr(u8)]
#[derive(Clone, Copy, Debug, FromPrimitive)]
pub enum AuthenAction {
    /// TAC_PLUS_AUTHEN_LOGIN
    Login = 0x01,
    /// TAC_PLUS_AUTHEN_CHPASS
    ChPass = 0x02,
    /// TAC_PLUS_AUTHEN_SENDAUTH
    SendAuth = 0x04,
}

/// The type of authentication as specified in an [`AuthenStart`] packet.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-5.1-7
#[repr(u8)]
#[derive(Clone, Copy, Debug, FromPrimitive)]
pub enum AuthenType {
    /// TAC_PLUS_AUTHEN_TYPE_ASCII
    Ascii = 0x01,
    /// TAC_PLUS_AUTHEN_TYPE_PAP
    Pap = 0x02,
    /// TAC_PLUS_AUTHEN_TYPE_CHAP
    Chap = 0x03,
    /// TAC_PLUS_AUTHEN_TYPE_MSCHAP
    MsChap = 0x05,
    /// TAC_PLUS_AUTHEN_TYPE_MSCHAPV2
    MsChapV2 = 0x06,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, FromPrimitive)]
pub enum AuthenService {
    /// TAC_PLUS_AUTHEN_SVC_NONE
    None = 0x00,
    /// TAC_PLUS_AUTHEN_SVC_LOGIN
    Login = 0x01,
    /// TAC_PLUS_AUTHEN_SVC_ENABLE
    Enable = 0x02,
    /// TAC_PLUS_AUTHEN_SVC_PPP
    Ppp = 0x03,
    /// TAC_PLUS_AUTHEN_SVC_PT
    Pt = 0x05,
    /// TAC_PLUS_AUTHEN_SVC_RCMD
    Rcmd = 0x06,
    /// TAC_PLUS_AUTHEN_SVC_X25
    X25 = 0x07,
    /// TAC_PLUS_AUTHEN_SVC_NASI
    Nasi = 0x08,
    /// TAC_PLUS_AUTHEN_SVC_FWPROXY
    FwProxy = 0x09,
}

/// A REPLY packet sent by the server.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-5.2
pub struct AuthenReply {
    pub status: AuthenStatus,
    pub flags: ReplyFlags,
    pub server_msg: Option<String>,
    pub data: Option<Vec<u8>>,
}

impl AuthenReply {
    pub fn to_bytes(&self, prev_header: Header, secret: &str) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::with_capacity(8);
        body.push(self.status.to_u8().unwrap());
        body.push(self.flags.bits());
        let server_msg_len = self.server_msg.as_ref().map_or(0, |v| v.len() as u16);
        body.extend_from_slice(&server_msg_len.to_be_bytes());
        let data_len = self.data.as_ref().map_or(0, |v| v.len() as u16);
        body.extend_from_slice(&data_len.to_be_bytes());
        if let Some(msg) = &self.server_msg {
            body.extend_from_slice(msg.as_ref())
        };
        if let Some(data) = &self.data {
            body.extend_from_slice(data)
        };

        let header = Header {
            version: TACACS_VERSION,
            packet_type: Type::Authentication,
            seq_no: prev_header.seq_no + 1,
            flags: Flags::empty(), // TODO: check  if previous header has "encryption" enabled
            session_id: prev_header.session_id,
            length: body.len() as _,
        };

        let mut buf = Vec::with_capacity(12 + body.len());

        buf.extend(header.to_bytes());

        let pad = header.psuedo_pad(secret);
        buf.extend(
            body.into_iter().zip(pad).map(|(a, b)| a ^ b)
        );

        buf
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum AuthenStatus {
    Pass = 0x01,
    Fail = 0x02,
    GetData = 0x03,
    GetUser = 0x04,
    GetPass = 0x05,
    Restart = 0x06,
    Error = 0x07,
    Follow = 0x21,
}

bitflags! {
    pub struct ReplyFlags: u8 {
        const NOECHO = 0x01;
    }
}

/// A CONTINUE packet sent by the client.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-5.3
#[derive(Clone, Debug)]
pub struct AuthenContinue {
    pub flags: ContinueFlags,
    pub user_msg: String,
    pub data: String,
}

impl AuthenContinue {
    pub fn from_bytes(bytes: &[u8], pad: Option<&[u8]>) -> Self {

        let decode = |index: u8| {
            let index = index as usize;
            if let Some(pad) = pad {
                bytes[index] ^ pad[index]
            } else {
                bytes[index]
            }
        };

        let decode_str = |start: u16, length: u16| {
            let start = (start + 5); // skip the first 8 bytes of the packet as they are fixed
            let end = start + length;

            (start..end)
                .map(|idx| decode(idx as _) as char)
                .collect::<String>()
        };

        let user_msg_len = NetworkEndian::read_u16(&[decode(0), decode(1)]);
        let data_len = NetworkEndian::read_u16(&[decode(2), decode(3)]);
        let flags = ContinueFlags::from_bits(decode(4)).expect("Failed to decode flags");

        Self {
            flags,
            user_msg: decode_str(0, user_msg_len as _),
            data: decode_str(user_msg_len, data_len),
        }
    }
}

bitflags! {
    pub struct ContinueFlags: u8 {
        const ABORT = 0x01;
    }
}