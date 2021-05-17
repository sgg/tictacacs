use std::io;

pub(super) fn load_byte_field(mut rdr: impl io::Read, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    rdr.read_exact(&mut buf)?;
    Ok(buf)
}

pub(super) fn load_string_field(rdr: impl io::Read, len: usize) -> io::Result<String> {
    let buf = load_byte_field(rdr, len)?;
    // FIXME(err): Return error on invalid UTF-8
    Ok(String::from_utf8(buf).expect("invalid UTF-8"))
}

