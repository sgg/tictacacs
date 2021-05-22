use std::io;

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};

use crate::packet::util::*;
use crate::packet::{Decode, Encode};

/// The packet body for an Authentication START request.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-5.1-3
///
/// ## Packet Format
///
/// ```plaintext
///  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |     status     |      flags     |        server_msg_len           |
/// +----------------+----------------+----------------+----------------+
/// |           data_len              |        server_msg ...
/// +----------------+----------------+----------------+----------------+
/// |           data ...
/// +----------------+----------------+
/// ```
#[derive(Clone, Debug)]
pub struct AuthenticationStart {
    pub action: Action,
    /// The privilege level that the user is authenticating as.
    pub priv_lvl: u8,
    pub authen_type: AuthenticationType,
    /// The service that is requesting authentication.
    pub authen_service: AuthenticationService,
    pub user: Option<String>,
    pub port: String,
    pub rem_addr: Option<String>,
    pub data: Vec<u8>,
}

impl Decode for AuthenticationStart {
    fn from_reader<R: io::Read>(mut rdr: R) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        rdr.read_exact(&mut buf)?;

        let action = Action::from_u8(buf[0]).expect("Failed to decode action");
        let priv_lvl = buf[1];
        let authen_type =
            AuthenticationType::from_u8(buf[2]).expect("Failed to decode authen_type");
        let authen_service =
            AuthenticationService::from_u8(buf[3]).expect("Failed to decode authen_service");

        let user = match buf[4] {
            0 => None,
            user_len => Some(load_string_field(&mut rdr, user_len as _)?),
        };

        let port = load_string_field(&mut rdr, buf[5] as _)?;

        let rem_addr = match buf[6] {
            0 => None,
            rem_addr_len => Some(load_string_field(&mut rdr, rem_addr_len as _)?),
        };

        let data = load_byte_field(&mut rdr, buf[7] as _)?;

        Ok(Self {
            action,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_addr,
            data,
        })
    }
}

/// The action of an authentication request.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-5.1-3
#[repr(u8)]
#[derive(Clone, Copy, Debug, FromPrimitive)]
pub enum Action {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromPrimitive)]
pub enum AuthenticationType {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromPrimitive)]
pub enum AuthenticationService {
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
pub struct AuthenticationReply {
    pub status: AuthenticationStatus,
    pub flags: ReplyFlags,
    pub server_msg: Option<String>,
    pub data: Option<Vec<u8>>,
}

impl Encode for AuthenticationReply {
    fn to_writer<W: io::Write>(&self, mut w: W) -> io::Result<usize> {
        let mut bytes_written = 0;
        bytes_written += w.write(&[self.status.to_u8().unwrap(), self.flags.bits()])?;

        let server_msg_len = self.server_msg.as_ref().map_or(0, |v| v.len() as u16);
        bytes_written += w.write(&server_msg_len.to_be_bytes())?;

        let data_len = self.data.as_ref().map_or(0, |v| v.len() as u16);
        bytes_written += w.write(&data_len.to_be_bytes())?;

        if let Some(msg) = &self.server_msg {
            bytes_written += w.write(msg.as_ref())?
        }

        if let Some(data) = &self.data {
            bytes_written += w.write(data)?
        }
        w.flush()?;

        Ok(bytes_written)
    }

    fn encoded_len(&self) -> usize {
        6 + self.server_msg.as_ref().map_or(0, String::len) + self.data.as_ref().map_or(0, Vec::len)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum AuthenticationStatus {
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
///
/// ## Packet Format
///
/// ```plaintext
///  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |          user_msg len           |            data_len             |
/// +----------------+----------------+----------------+----------------+
/// |     flags      |  user_msg ...
/// +----------------+----------------+----------------+----------------+
/// |    data ...
/// +----------------+
/// ```
#[derive(Clone, Debug)]
pub struct AuthenticationContinue {
    pub flags: ContinueFlags,
    pub user_msg: String,
    pub data: Vec<u8>,
}

impl Decode for AuthenticationContinue {
    fn from_reader<R: io::Read>(mut rdr: R) -> io::Result<Self> {
        let mut buf = [0u8; 5];
        rdr.read_exact(&mut buf)?;
        let user_msg_len = NetworkEndian::read_u16(&buf[..]);
        let data_len = NetworkEndian::read_u16(&buf[2..]);
        let flags = ContinueFlags::from_bits(buf[4]).expect("failed to decode flags");

        let user_msg = load_string_field(&mut rdr, user_msg_len as _)?;
        let data = load_byte_field(&mut rdr, data_len as _)?;
        Ok(Self {
            flags,
            user_msg,
            data,
        })
    }
}

bitflags! {
    pub struct ContinueFlags: u8 {
        const ABORT = 0x01;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod authentication_request {
        use super::*;

        #[test]
        fn test_decode() {
            todo!()
        }

        #[test]
        fn test_encode_account_body() {
            todo!()
        }

        #[test]
        fn test_encoded_len() {
            todo!()
        }
    }

    mod authentication_reply {
        use super::*;

        #[test]
        fn test_decode() {
            todo!()
        }

        #[test]
        fn test_encode_account_body() {
            todo!()
        }

        #[test]
        fn test_encoded_len() {
            todo!()
        }
    }

    mod authentication_continue {
        use super::*;

        #[test]
        fn test_decode() {
            todo!()
        }

        #[test]
        fn test_encode_account_body() {
            todo!()
        }

        #[test]
        fn test_encoded_len() {
            todo!()
        }
    }
}
