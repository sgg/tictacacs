use std::io::{self, Read, Write};

use bitflags::bitflags;
use num_traits::FromPrimitive;

use crate::packet::authentication::{AuthenticationService, AuthenticationType};
use crate::packet::authorization::{Argument, AuthenMethod};
use crate::packet::util::*;
use crate::packet::{Decode, Encode};
use byteorder::{ByteOrder, NetworkEndian};

/// An account REQUEST body sent by a client.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-7.1
///
/// ## Packet Format
///
/// ```plaintext
///  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |      flags     |  authen_method |    priv_lvl    |  authen_type   |
/// +----------------+----------------+----------------+----------------+
/// | authen_service |    user_len    |    port_len    |  rem_addr_len  |
/// +----------------+----------------+----------------+----------------+
/// |    arg_cnt     |   arg_1_len    |   arg_2_len    |      ...       |
/// +----------------+----------------+----------------+----------------+
/// |   arg_N_len    |    user ...
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
pub struct AccountRequest {
    flags: Option<Flags>,
    authen_method: AuthenMethod,
    priv_lvl: u8,
    authen_type: AuthenticationType,
    authen_service: AuthenticationService,
    user: String,
    port: String,
    rem_addr: Option<String>,
    args: Option<Vec<Argument>>,
}

impl Decode for AccountRequest {
    fn from_reader<R: io::Read>(mut rdr: R) -> io::Result<Self> {
        let mut buf = [0u8; 9];
        rdr.read(&mut buf)?;

        let flags = Flags::from_bits(buf[0]);
        let authen_method = AuthenMethod::from_u8(buf[1]).expect("failed to decode authen_method");
        let priv_lvl = buf[2];
        let authen_type =
            AuthenticationType::from_u8(buf[3]).expect("failed to decode authen_type");
        let authen_service =
            AuthenticationService::from_u8(buf[4]).expect("failed to decode authen_service");
        let (user_len, port_len, rem_addr_len, arg_count) = match buf[5..] {
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
            flags,
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

impl Encode for AccountRequest {
    fn to_writer<W: io::Write>(&self, mut w: W) -> io::Result<usize> {
        let mut bytes_written = 0;
        let mut first_bytes = [
            self.flags.as_ref().map_or(0, Flags::bits),
            self.authen_method as _,
            self.priv_lvl,
            self.authen_type as _,
            self.authen_service as _,
            self.user.len() as _,
            self.port.len() as _,
            self.rem_addr.as_ref().map_or(0, String::len) as _,
            self.args.as_ref().map_or(0, Vec::len) as _,
        ];

        bytes_written += w.write(&first_bytes)?;

        // write arg lens
        if let Some(args) = &self.args {
            let arg_lens: Vec<u8> = args.iter().map(|arg| arg.encoded_len() as _).collect();
            bytes_written += w.write(&arg_lens)?;
        }
        bytes_written += w.write(&self.user.as_bytes())?;
        bytes_written += w.write(&self.port.as_bytes())?;
        if let Some(rem_addr) = &self.rem_addr {
            bytes_written += w.write(rem_addr.as_bytes())?
        }

        if let Some(args) = &self.args {
            for arg in args {
                bytes_written += w.write(arg.to_string().as_bytes())?
            }
        }

        Ok(bytes_written)
    }

    fn encoded_len(&self) -> usize {
        let (arg_count, total_arg_len) = match &self.args {
            None => (0, 0),
            Some(args) => (args.len(), args.iter().map(Argument::encoded_len).sum()),
        };

        9 + arg_count
            + self.user.len()
            + self.port.len()
            + self.rem_addr.as_ref().map_or(0, String::len)
            + total_arg_len
    }
}

bitflags! {
    /// Flags that may be set on an [`AccountRequest`]
    pub struct Flags: u8 {
        const START = 0x02;
        const STOP = 0x04;
        const WATCHDOG = 0x08;
    }
}

/// An account REPLY body sent by a server.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#section-7.2
///
/// ## Packet Format
///
/// ```plaintext
///   1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |         server_msg len          |            data_len             |
/// +----------------+----------------+----------------+----------------+
/// |     status     |         server_msg ...
/// +----------------+----------------+----------------+----------------+
/// |     data ...
/// +----------------+
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountReply {
    server_msg: Option<String>,
    data: Option<String>,
    status: Option<Status>,
}

impl Decode for AccountReply {
    fn from_reader<R: io::Read>(mut rdr: R) -> io::Result<Self> {
        let mut buf = [0u8; 5];
        rdr.read_exact(&mut buf)?;

        let server_msg_len = NetworkEndian::read_u16(&buf[0..2]);
        let data_len = NetworkEndian::read_u16(&buf[2..4]);
        let status = Status::from_bits(buf[4]);

        let server_msg = match server_msg_len {
            0 => None,
            len => Some(load_string_field(&mut rdr, len as _)?),
        };
        let data = match data_len {
            0 => None,
            len => Some(load_string_field(&mut rdr, len as _)?),
        };

        Ok(Self {
            server_msg,
            data,
            status,
        })
    }
}

impl Encode for AccountReply {
    fn to_writer<W: io::Write>(&self, mut w: W) -> io::Result<usize> {
        let mut bytes_written = 0;
        let mut buf = [0u8; 5];
        if let Some(msg) = &self.server_msg {
            NetworkEndian::write_u16(&mut buf[0..], msg.len() as _)
        }
        if let Some(data) = &self.data {
            NetworkEndian::write_u16(&mut buf[0..], data.len() as _)
        }

        if let Some(status) = &self.status {
            buf[4] = status.bits();
        }
        bytes_written += w.write(&buf)?;

        if let Some(msg) = &self.server_msg {
            bytes_written += w.write(msg.as_bytes())?;
        }
        if let Some(data) = &self.data {
            bytes_written += w.write(data.as_bytes())?;
        }

        Ok(bytes_written)
    }

    fn encoded_len(&self) -> usize {
        5 + self.server_msg.as_ref().map_or(0, String::len)
            + self.data.as_ref().map_or(0, String::len)
    }
}

bitflags! {
    /// The status for an [`AccountReply`] body.
    ///
    /// https://www.rfc-editor.org/rfc/rfc8907.html#section-7.2-3
    pub struct Status: u8 {
        const SUCCESS = 0x01;
        const ERROR = 0x02;
        const FOLLOW = 0x21;
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::str::FromStr;

    use super::*;

    mod account_request {
        use super::*;

        fn test_request() -> AccountRequest {
            let args = ["service=shell", "cmd=debug", "cmdarg=aaa"]
                .iter()
                .copied()
                .map(Argument::from_str)
                .collect::<Result<_, _>>()
                .unwrap();

            AccountRequest {
                flags: Some(Flags::START),
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
            &include_bytes!("../../tests/data/1621709055896_body_account.bin")[..]
        }

        #[test]
        fn test_decode() {
            let decoded = AccountRequest::from_reader(test_body()).expect("failed decode account");
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

    mod account_reply {

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
