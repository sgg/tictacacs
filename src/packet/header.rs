use std::fmt;
use std::io;

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use md5::Digest;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};

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
    pub body_length: u32,
}

impl Header {
    /// Return the major version of the TACACS+ protocol.
    pub fn major_version(&self) -> u8 {
        (self.version & 0xf0) >> 4
    }

    /// Return the minor version of the TACACS+ protocol.
    pub fn minor_version(&self) -> u8 {
        self.version & 0x0f
    }

    /// Copy the header, incrementing the sequence number.
    pub fn with_next_seq_no(&self) -> Self {
        let mut h = *self;
        h.seq_no += 1;
        h
    }

    /// Copy the header, setting the body length.
    pub fn with_body_length(&self, body_length: u32) -> Self {
        let mut h = *self;
        h.body_length = body_length;
        h
    }

    /// Decode a `Header` from the reader.
    ///
    /// This function will read at most 12 bytes from the reader.
    pub fn from_reader(mut rdr: impl io::Read) -> io::Result<Self> {
        // FIXME(err): this should be fallible
        let mut buf = [0u8; 12];
        rdr.read_exact(&mut buf)?;
        Ok(Self {
            version: buf[0],
            packet_type: Type::from_u8(buf[1]).expect("Failed to parse packet type"),
            seq_no: buf[2],
            flags: Flags::from_bits(buf[3]).expect("Failed to parse flags"),
            session_id: NetworkEndian::read_u32(&buf[4..8]),
            body_length: NetworkEndian::read_u32(&buf[8..12]),
        })
    }

    /// Encode the header into a vector of bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        self.to_writer(&mut buf).unwrap();
        buf
    }

    /// Encode the header into the writer.
    pub fn to_writer(&self, mut w: impl io::Write) -> io::Result<usize> {
        let mut written = 0;

        // FIXME(perf): since headers are of fixed size we could pre-alloc a buffer on the stack s.t. we only call write once.
        written += w.write(&[
            self.version,
            self.packet_type.to_u8().unwrap(),
            self.seq_no,
            self.flags.bits(),
        ])?;
        written += w.write(self.session_id.to_be_bytes().as_ref())?;
        written += w.write(self.body_length.to_be_bytes().as_ref())?;
        w.flush()?;

        Ok(written)
    }

    /// Calculate the pseudo_pad used to de-obfuscate the data associated with this packet.
    ///
    /// If the `UNENCRYPTED` flag is set, this will return an empty vector of the appropriate length.
    ///
    /// https://www.rfc-editor.org/rfc/rfc8907.html#name-data-obfuscation
    pub fn pseudo_pad(&self, secret_key: &str) -> Vec<u8> {
        if !self.is_obfuscated() {
            // we return a zero vector s.t. the XOR based pad algorithm always returns the original data
            return vec![0, self.body_length as _];
        }

        let mut final_pad = Vec::with_capacity(self.body_length as _);
        let mut pad = self.initial_pad(secret_key);
        final_pad.extend_from_slice(&pad);

        while final_pad.len() < self.body_length as _ {
            pad = self.subsequent_pad(&pad, secret_key);
            final_pad.extend_from_slice(&pad)
        }

        final_pad.truncate(self.body_length as _);
        final_pad
    }

    /// Calculate the initial pad used for data obfuscation
    ///
    /// https://www.rfc-editor.org/rfc/rfc8907.html#name-data-obfuscation
    fn initial_pad(&self, secret: &str) -> [u8; 16] {
        let mut hasher = md5::Md5::new();
        // MD5_1 = MD5{session_id, key, version, seq_no}
        hasher.update(self.session_id.to_be_bytes()); // the session id must be provided in network byte order
        hasher.update(secret.as_bytes());
        hasher.update([self.version]);
        hasher.update([self.seq_no]);
        hasher.finalize().into()
    }

    fn subsequent_pad(&self, prev_pad: &[u8], secret: &str) -> [u8; 16] {
        let mut hasher = md5::Md5::new();
        hasher.update(self.session_id.to_be_bytes());
        hasher.update(secret.as_bytes());
        hasher.update([self.version]);
        hasher.update([self.seq_no]);
        hasher.update(prev_pad);

        hasher.finalize().into()
    }

    /// Return true if the `UNENCRYPTED` flag is unset.
    pub fn is_obfuscated(&self) -> bool {
        !self.flags.contains(Flags::UNENCRYPTED)
    }

    /// Create a [`BodyDecoder`] that can decode the body associated with this header.
    pub fn body_decoder(
        &self,
        secret_key: impl AsRef<str>,
        rdr: impl io::Read,
    ) -> BodyDecoder<impl io::Read> {
        BodyDecoder {
            offset: 0,
            pad: self.pseudo_pad(secret_key.as_ref()),
            inner: rdr,
        }
    }
}

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
    Account = 0x03,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Type::Authentication => "authentication",
            Type::Authorization => "authorization",
            Type::Account => "account",
        };
        write!(f, "{}", s)
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
        /// Used to allow a client and server to negotiate "Single Connection Mode".
        const SINGLE_CONNECT_FLAG = 0x04;
    }
}

pub struct BodyDecoder<R: io::Read> {
    offset: usize,
    pad: Vec<u8>,
    inner: R,
}

impl<R: io::Read> io::Read for BodyDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let start = self.offset;

        let bytes_read = self.inner.read(buf)?;
        buf.iter_mut()
            .zip(&self.pad[start..])
            .for_each(|(out, pad_byte)| *out ^= pad_byte);

        self.offset += bytes_read;
        Ok(bytes_read)
    }
}
