use std::collections::HashMap;
use std::fmt;
use std::io;
use std::str::FromStr;

use byteorder::{ByteOrder, NetworkEndian};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};

use crate::packet::authentication::{AuthenticationService, AuthenticationType};
use crate::packet::util::*;
use crate::packet::{Decode, Encode};

/// The packet body for an Authentication REQUEST.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-6.1
///
/// ## Packet Format
///
/// ```plaintext
///  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |  authen_method |    priv_lvl    |  authen_type   | authen_service |
/// +----------------+----------------+----------------+----------------+
/// |    user_len    |    port_len    |  rem_addr_len  |    arg_cnt     |
/// +----------------+----------------+----------------+----------------+
/// |   arg_1_len    |   arg_2_len    |      ...       |   arg_N_len    |
/// +----------------+----------------+----------------+----------------+
/// |   user ...
/// +----------------+----------------+----------------+----------------+
/// |   port ...
/// +----------------+----------------+----------------+----------------+
/// |   rem_addr ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_1 ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_2 ...
/// +----------------+----------------+----------------+----------------+
/// |   ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_N ...
/// +----------------+----------------+----------------+----------------+
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    pub authen_method: AuthenMethod,
    pub priv_lvl: u8,
    pub authen_type: AuthenticationType,
    pub authen_service: AuthenticationService,
    pub user: String,
    pub port: String,
    pub rem_addr: Option<String>,
    pub args: Option<Vec<Argument>>,
}

impl Encode for AuthorizationRequest {
    fn to_writer<W: io::Write>(&self, w: W) -> io::Result<usize> {
        todo!()
    }

    fn encoded_len(&self) -> usize {
        todo!()
    }
}

impl Decode for AuthorizationRequest {
    fn from_reader<R: io::Read>(mut rdr: R) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        rdr.read_exact(&mut buf)?;

        // TODO: this implementation is WRONG, we need to read arg lens before we start reading data
        let authen_method = AuthenMethod::from_u8(buf[0]).expect("failed to decode authen_method");
        let priv_lvl = buf[1];
        let authen_type =
            AuthenticationType::from_u8(buf[2]).expect("failed to decode authen_type");
        let authen_service =
            AuthenticationService::from_u8(buf[3]).expect("failed to decode authen_service");

        let (user_len, port_len, rem_addr_len, arg_count) = match buf[4..] {
            [ul, pl, rl, al] => (ul, pl, rl, al),
            _ => unreachable!(),
        };
        let arg_lens = load_arg_lens(&mut rdr, arg_count as _)?;

        let user = load_string_field(&mut rdr, user_len as _)?;
        let port = load_string_field(&mut rdr, port_len as _)?;
        let rem_addr = match rem_addr_len {
            0 => None,
            len => Some(load_string_field(&mut rdr, len as _)?),
        };
        let args = match arg_lens.len() {
            0 => None,
            _ => Some(load_arg_fields(&mut rdr, &arg_lens)?),
        };

        Ok(Self {
            authen_method,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_addr,
            args,
        })
    }
}

/// The authentication method used to acquire user credentials.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum AuthenMethod {
    NotSet = 0x00,
    None = 0x01,
    Krb5 = 0x02,
    Line = 0x03,
    Enable = 0x04,
    Local = 0x05,
    TacacsPlus = 0x06,
    Guest = 0x08,
    Radius = 0x10,
    Krb4 = 0x11,
    Rcmd = 0x2F,
}

/// An argument provided in an Authentication or Authorization request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Argument {
    pub name: String,
    pub value: String,
    pub mandatory: bool,
}

impl Argument {
    /// The number of bytes in the encoded argument.
    pub fn encoded_len(&self) -> usize {
        self.name.len() + self.value.len() + 1
    }
}

impl FromStr for Argument {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once(&['=', '*'][..]) {
            Some((name, value)) => {
                // if this matched then this index must be an ASCII char on a boundary
                let mandatory = match s.as_bytes()[name.len()] as char {
                    '=' => true,
                    '*' => false,
                    _ => unreachable!(),
                };

                Ok(Self {
                    name: name.to_string(),
                    value: value.to_string(),
                    mandatory,
                })
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "arg is missing delimiter",
            )),
        }
    }
}

impl fmt::Display for Argument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sep_char = match self.mandatory {
            true => '=',
            false => '*',
        };
        write!(f, "{}{}{}", self.name, sep_char, self.value)
    }
}

/// The packet body for an Authentication REPLY.
///
///
/// ## Packet Format
///
/// ```plaintext
///  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |    status      |     arg_cnt    |         server_msg len          |
/// +----------------+----------------+----------------+----------------+
/// +            data_len             |    arg_1_len   |    arg_2_len   |
/// +----------------+----------------+----------------+----------------+
/// |      ...       |   arg_N_len    |         server_msg ...
/// +----------------+----------------+----------------+----------------+
/// |   data ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_1 ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_2 ...
/// +----------------+----------------+----------------+----------------+
/// |   ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_N ...
/// +----------------+----------------+----------------+----------------+
/// ```
#[derive(Clone, Debug)]
pub struct AuthorizationReply {
    pub status: AuthorizationStatus,
    pub args: Vec<Argument>,
    pub server_msg: Option<String>,
    pub data: Option<String>,
}

impl Encode for AuthorizationReply {
    fn to_writer<W: io::Write>(&self, mut w: W) -> io::Result<usize> {
        let mut bytes_written = 0;

        let mut buf = [0u8; 6];
        buf[0] = self.status.to_u8().unwrap();
        buf[1] = self.args.len() as u8;

        let server_msg_len = self.server_msg.as_ref().map_or(0, String::len) as _;
        NetworkEndian::write_u16(&mut buf[2..4], server_msg_len);

        let data_len = self.data.as_ref().map_or(0, String::len) as _;
        NetworkEndian::write_u16(&mut buf[4..6], data_len);

        bytes_written += w.write(&buf)?;
        for arg in &self.args {
            bytes_written += w.write(arg.to_string().as_bytes())?;
        }

        w.flush()?;

        Ok(bytes_written)
    }

    fn encoded_len(&self) -> usize {
        6 + self.data.as_ref().map_or(0, String::len)
            + self.server_msg.as_ref().map_or(0, String::len)
            + self.args.iter().map(Argument::encoded_len).sum::<usize>()
    }
}

impl Decode for AuthorizationReply {
    fn from_reader<R: io::Read>(rdr: R) -> io::Result<Self> {
        todo!()
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
pub enum AuthorizationStatus {
    PassAdd = 0x01,
    PassRepl = 0x02,
    Fail = 0x10,
    Error = 0x11,
    Follow = 0x21,
}

#[cfg(test)]
mod tests {
    use super::*;

    mod authorization_request {
        use super::*;

        fn test_request() -> AuthorizationRequest {
            let args = ["service=shell", "cmd=show", "cmdarg=version"]
                .iter()
                .copied()
                .map(Argument::from_str)
                .collect::<Result<_, _>>()
                .unwrap();

            AuthorizationRequest {
                authen_method: AuthenMethod::TacacsPlus,
                priv_lvl: 0,
                authen_type: AuthenticationType::Ascii,
                authen_service: AuthenticationService::Login,
                user: "myuser2".to_string(),
                port: "python_tty0".to_string(),
                rem_addr: Some("python_device".to_string()),
                args: Some(args),
            }
        }
        fn test_body() -> &'static [u8] {
            &include_bytes!("../../tests/data/1621708984374_body_authorization.bin")[..]
        }

        #[test]
        fn test_decode() {
            let decoded = AuthorizationRequest::from_reader(test_body())
                .expect("failed to decode authZ request");
            assert_eq!(decoded, test_request())
        }

        #[test]
        fn test_encode_account_body() {
            let encoded = test_request().to_bytes();
            assert_eq!(encoded, test_body())
        }

        #[test]
        fn test_encoded_len() {
            assert_eq!(test_request().encoded_len(), test_body().len())
        }
    }
    mod authorization_reply {
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
