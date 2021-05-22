use std::io::{self};

/// TACACS+ accounting packet bodies.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#name-accounting
pub mod accounting;

/// TACACS+ authentication packet bodies.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#name-authentication
pub mod authentication;

/// TACACS+ authorization packet bodies.
///
/// https://www.rfc-editor.org/rfc/rfc8907.html#name-authorization
pub mod authorization;

/// TACACS+ header bodies and fields.
pub mod header;

mod util;

/// A trait for TACACS+ packet bodies that can be encoded.
pub trait Encode {
    /// Serialize the data as a vector.
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.to_writer(&mut buf).unwrap();
        buf
    }

    /// Serialize the payload into the IO stream.
    fn to_writer<W: io::Write>(&self, w: W) -> io::Result<usize>;

    /// Return the encoded length of the body.
    fn encoded_len(&self) -> usize;
}

/// A trait for TACACS+ packet bodies that can be decoded from bytes
pub trait Decode {
    // FIXME(error): use a crate specific error rather than io::Error
    fn from_reader<R: io::Read>(rdr: R) -> io::Result<Self>
    where
        Self: Sized;
}
