use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::io::{Error, Read, Write};
use std::net::{TcpListener, TcpStream};

use log::*;
use tictacacs::packet::authentication::*;
use tictacacs::packet::header::*;
use tictacacs::packet::*;

const SHARED_SECRET: &str = "my_shared_key";
const HEADER_LENGTH: usize = 12;

/// Encode a packet header and body.
pub fn write_packet_to_vec(
    header: header::Header,
    body: &impl Encode,
    secret_key: &str,
) -> Vec<u8> {
    let pad = header.pseudo_pad(secret_key);
    let mut buf = Vec::with_capacity(HEADER_LENGTH + header.body_length as usize);
    buf.extend_from_slice(&header.to_bytes());

    let body_bytes = body.to_bytes();
    buf.extend(body_bytes.into_iter().zip(pad).map(|(a, b)| a ^ b));

    buf
}

/// Encode a packet header and body into the writer.
///
/// Consider using a buffered writer to minimize syscalls.
pub fn write_packet<W: io::Write>(
    mut w: W,
    header: header::Header,
    body: &impl Encode,
    secret_key: &str,
) -> io::Result<usize> {
    struct Encoder<I> {
        offset: usize,
        pad: Vec<u8>,
        inner: I,
    }

    impl<I> Encoder<I> {
        fn new(pad: Vec<u8>, writer: I) -> Self {
            Self {
                offset: 0,
                pad,
                inner: writer,
            }
        }
    }
    impl<I: io::Write> io::Write for Encoder<I> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let start = self.offset;
            let end = start + buf.len();
            assert!(
                end <= self.pad.len(),
                "buf overruns pad length, violating the protocol. This is likely a bug."
            );

            let out_buf = &mut self.pad[start..end];
            out_buf
                .iter_mut()
                .zip(buf)
                // xor each byte in the pad buffer with the input data
                .for_each(|(out, input)| *out ^= input);

            let written = self.inner.write(&out_buf)?;
            self.offset += written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    // write the header
    let mut written = 0;

    written += header.to_writer(&mut w)?;

    written += if header.is_obfuscated() {
        // FIXME(alloc): we could probably calculate this lazily and avoid the vec allocation
        let encoder = Encoder::new(header.pseudo_pad(secret_key), w);
        body.to_writer(encoder)?
    } else {
        body.to_writer(w)?
    };

    Ok(written)
}

pub fn read_packet<D: Decode>(
    mut rdr: impl io::Read,
    secret_key: &str,
) -> io::Result<(header::Header, D)> {
    struct Decoder<R> {
        offset: usize,
        pad: Vec<u8>,
        inner: R,
    }
    impl<R: io::Read> io::Read for Decoder<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let start = self.offset;
            let end = start + buf.len();
            assert!(
                end <= self.pad.len(),
                "buf overruns pad length. offset/start/end: {}/{}/{}",
                self.offset, start, end
            );
            let bytes_read = self.inner.read(buf)?;
            buf.iter_mut()
                .zip(&self.pad[start..end])
                .for_each(|(out, pad_byte)| *out ^= pad_byte);

            self.offset += bytes_read;
            Ok(bytes_read)
        }
    }

    let header = header::Header::from_reader(&mut rdr)?;
    trace!("Decoded header {:#?}", header);

    let body = if header.is_obfuscated() {
        let decoder = Decoder {
            offset: 0,
            pad: header.pseudo_pad(secret_key),
            inner: rdr,
        };

        D::from_reader(decoder)
    } else {
        D::from_reader(rdr)
    }?;

    Ok((header, body))
}

fn handle_stream(mut stream: TcpStream, pw_db: &HashMap<String, String>) -> io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    info!("Peer {:?} connected!", peer_addr);
    let mut buffer = vec![0u8; 2 << 15]; // A typical TACACS+ packet should be less than 64k

    let mut username = None;

    let mut step = 0;
    loop {
        match step {
            0 => {
                let (header, auth_start): (_, Start) = read_packet(&mut stream, SHARED_SECRET)?;

                info!("Parsed Header: {:#?}", header);
                info!(
                    "Version {:x} {:x}",
                    header.major_version(),
                    header.minor_version()
                );
                info!("Session ID {:x}", header.session_id);

                info!("AuthenStart: {:#?}", auth_start);
                username = auth_start.user;

                let reply = AuthenticationReply {
                    status: AuthenticationStatus::GetPass,
                    flags: ReplyFlags::empty(),
                    server_msg: None,
                    data: None,
                };
                write_packet(
                    &mut stream,
                    header.with_next_seq_no().with_body_length(reply.len() as _),
                    &reply,
                    SHARED_SECRET,
                )?;
            }
            1 => {
                let (header, auth_continue): (_, AuthenticationContinue) = read_packet(&mut stream, SHARED_SECRET)?;
                info!("AuthenContinue: {:#?}", auth_continue);
                let pwd = auth_continue.user_msg;

                let reply = match pw_db.get(username.as_ref().unwrap()) {
                    Some(expected) if &pwd == expected => AuthenticationReply {
                        status: AuthenticationStatus::Pass,
                        flags: ReplyFlags::empty(),
                        server_msg: Some("good work".to_string()),
                        data: None,
                    },
                    Some(_) => AuthenticationReply {
                        status: AuthenticationStatus::Fail,
                        flags: ReplyFlags::empty(),
                        server_msg: Some("invalid password".to_string()),
                        data: None,
                    },
                    None => AuthenticationReply {
                        status: AuthenticationStatus::Fail,
                        flags: ReplyFlags::empty(),
                        server_msg: Some("failed to authenticate user".to_string()),
                        data: None,
                    },
                };

                write_packet(
                    &mut stream,
                    header.with_next_seq_no().with_body_length(reply.len() as _),
                    &reply,
                    SHARED_SECRET
                )?;
            }
            _ => {
                if stream.read(&mut buffer)? != 0 {
                    unimplemented!("ASCII auth should take exactly 2 steps");
                }
                info!("EOF. Closing stream for peer {:x?}", peer_addr);
                return Ok(());
            }
        }

        step += 1;

    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    info!("Listening...");

    let pw_db: HashMap<String, String> = [
        ("bob", "password123"),
        ("alice", "Star-Both-Circular-Grand-9"),
        ("myuser", "mypass"),
        ("myuser2", "mypass"),
    ]
    .iter()
    .map(|(un, pw)| (un.to_string(), pw.to_string()))
    .collect();

    let listener = TcpListener::bind("127.0.0.1:10049").map_err(|e| {
        error!("Failed to bind -- {}", e);
        e
    })?;

    for stream in listener.incoming() {
        let stream = stream.map_err(|e| {
            error!("Failed to open connection -- {}", e);
            e
        })?;
        handle_stream(stream, &pw_db)?;
    }

    Ok(())
}