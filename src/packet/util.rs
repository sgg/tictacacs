use std::io;
use std::str::FromStr;

use crate::packet::authorization::Argument;

pub(super) fn load_byte_field(mut rdr: impl io::Read, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    rdr.read_exact(&mut buf)?;
    Ok(buf)
}

/// Load a field UTF-8 field from a reader as a String.
///
/// This function is useful for loading variable length fields from a packet body.
/// This function **will** advance the reader.
pub(super) fn load_string_field(rdr: impl io::Read, len: usize) -> io::Result<String> {
    let buf = load_byte_field(rdr, len)?;
    // FIXME(err): Return error on invalid UTF-8
    Ok(String::from_utf8(buf).expect("invalid UTF-8"))
}

pub(super) fn load_arg_lens(mut rdr: impl io::Read, arg_count: usize) -> io::Result<Vec<u8>> {
    let mut arg_lens = vec![0u8; arg_count];
    rdr.read_exact(&mut arg_lens)?;
    Ok(arg_lens)
}

pub(super) fn load_arg_fields(
    mut rdr: impl io::Read,
    arg_lens: impl AsRef<[u8]>,
) -> io::Result<Vec<Argument>> {
    let arg_lens = arg_lens.as_ref();
    arg_lens
        .iter()
        .copied()
        .map(|arg_len| {
            load_string_field(&mut rdr, arg_len as _).and_then(|s| Argument::from_str(&s))
        })
        .try_fold(Vec::with_capacity(arg_lens.len()), |mut acc, maybe_arg| {
            match maybe_arg {
                Ok(arg) => acc.push(arg),
                Err(e) => return Err(e),
            }
            Ok(acc)
        })
}
