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
#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    pub authen_method: AuthenMethod,
    pub priv_lvl: u8,
    pub authen_type: AuthenticationType,
    pub authen_service: AuthenticationService,
    pub user: String,
    pub port: String,
    pub rem_addr: Option<String>,
    pub args: HashMap<String, Argument>,
}

impl Decode for AuthorizationRequest {
    fn from_reader<R: io::Read>(mut rdr: R) -> io::Result<Self> {
        let mut preamble_buf = [0u8; 8];
        rdr.read_exact(&mut preamble_buf)?;

        let authen_method =
            AuthenMethod::from_u8(preamble_buf[0]).expect("Failed to decode authen_method");
        let priv_lvl = preamble_buf[1];
        let authen_type =
            AuthenticationType::from_u8(preamble_buf[2]).expect("Failed to decode authen_type");
        let authen_service = AuthenticationService::from_u8(preamble_buf[3])
            .expect("Failed to decode authen_service");

        let user = load_string_field(&mut rdr, preamble_buf[4] as _)?;
        let port = load_string_field(&mut rdr, preamble_buf[5] as _)?;
        let rem_addr = match preamble_buf[6] {
            0 => None,
            rem_addr_len => Some(load_string_field(&mut rdr, rem_addr_len as _)?),
        };

        let arg_count = preamble_buf[7] as usize;
        let arg_lengths = {
            let mut length_buf = vec![0u8; arg_count];
            rdr.read_exact(&mut length_buf)?;
            length_buf
        };

        let mut args = HashMap::with_capacity(arg_count);
        for arg_len in arg_lengths {
            let arg: Argument = load_string_field(&mut rdr, arg_len as _)?.parse()?;
            args.insert(arg.name.clone(), arg);
        }

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
#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
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
#[derive(Clone, Debug)]
pub struct Argument {
    pub name: String,
    pub value: String,
    pub mandatory: bool,
}

impl Argument {
    /// The number of bytes in the encoded argument.
    pub fn len(&self) -> usize {
        self.name.len() + self.value.len() + 1
    }
}

impl FromStr for Argument {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((name, value)) = s.split_once('=') {
            return Ok(Argument {
                name: name.to_string(),
                value: value.to_string(),
                mandatory: true,
            });
        }
        if let Some((name, value)) = s.split_once('*') {
            return Ok(Argument {
                name: name.to_string(),
                value: value.to_string(),
                mandatory: false,
            });
        }

        panic!("argument is not encoded properly")
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
    fn to_bytes(&self) -> Vec<u8> {
        todo!()
    }

    fn to_writer<W: io::Write>(&self, mut w: W) -> io::Result<usize> {
        let mut written = 0;

        let mut preamble_buf = [0u8; 6];
        preamble_buf[0] = self.status.to_u8().unwrap();
        preamble_buf[1] = self.args.len() as u8;

        let server_msg_len = self.server_msg.as_ref().map_or(0, String::len) as _;
        NetworkEndian::write_u16(&mut preamble_buf[2..4], server_msg_len);

        let data_len = self.data.as_ref().map_or(0, String::len) as _;
        NetworkEndian::write_u16(&mut preamble_buf[4..6], data_len);

        written += w.write(&preamble_buf)?;
        for arg in &self.args {
            written += w.write(arg.to_string().as_bytes())?;
        }

        w.flush()?;

        Ok(written)
    }

    fn len(&self) -> usize {
        6 + self.data.as_ref().map_or(0, String::len)
            + self.server_msg.as_ref().map_or(0, String::len)
            + self.args.iter().map(Argument::len).sum::<usize>()
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
