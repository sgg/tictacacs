use std::io::{Read, Error, Write};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::convert::TryInto;
use std::collections::HashMap;

use log::*;
use tictacacs::packet::*;

const SHARED_SECRET: &str = "my_shared_key";

fn handle_stream(mut stream: TcpStream, pw_db: &HashMap<String, String>) -> io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    info!("Peer {:?} connected!", peer_addr);
    let mut buffer = vec![0u8;2<<15]; // A typical tacacs+ packet should be less than 64k

    let mut username = None;
    loop {
        match stream.read(&mut buffer) {
            Err(e) => {
                error!("Failed to read buffer -- {}", e);
                return Err(e)
            }
            Ok(bytes_read) if bytes_read == 0 => {
                info!("EOF. Closing stream for peer {:x?}", peer_addr);
                return Ok(())
            }
            Ok(bytes_read) => {
                info!("Read {} bytes", bytes_read);
                let packet = &buffer[..bytes_read];
                let body = &packet[12..];

                let header = Header::from_bytes(&packet[..12]);
                info!("Parsed Header: {:#?}", header);
                info!("Version {:x} {:x}", header.major_version(), header.minor_version());
                info!("Session ID {:x}", header.session_id);

                let reply = match header.seq_no {
                    1 => {
                        let auth_start = AuthenStart::from_bytes(body, Some(header.psuedo_pad(SHARED_SECRET).as_ref()));
                        username = auth_start.user;
                        // tell the client to send the password
                        AuthenReply {
                            status: AuthenStatus::GetPass,
                            flags: ReplyFlags::empty(),
                            server_msg: None,
                            data: None,
                        }.to_bytes(header, SHARED_SECRET)
                    },
                    3 => {
                        let auth_continue = AuthenContinue::from_bytes(&body, Some(header.psuedo_pad(SHARED_SECRET).as_slice()));
                        info!("AuthenContinue: {:#?}", auth_continue);
                        let pwd = auth_continue.user_msg;

                        match pw_db.get(username.as_ref().unwrap()) {
                            Some(expected) if &pwd == expected => {
                                AuthenReply {
                                    status: AuthenStatus::Pass,
                                    flags: ReplyFlags::empty(),
                                    server_msg: Some("good work".to_string()),
                                    data: None
                                }
                            },
                            Some(_) => {
                                AuthenReply {
                                    status: AuthenStatus::Fail,
                                    flags: ReplyFlags::empty(),
                                    server_msg: Some("invalid password".to_string()),
                                    data: None
                                }
                            },
                            None => {
                                AuthenReply {
                                    status: AuthenStatus::Fail,
                                    flags: ReplyFlags::empty(),
                                    server_msg: Some("failed to authenticate user".to_string()),
                                    data: None
                                }
                            }
                        }
                            .to_bytes(header, SHARED_SECRET)
                    }
                    _ => unimplemented!()
                };

                stream.write(reply.as_slice())?;
                stream.flush()?;
            }
        }
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

    let listener = TcpListener::bind("127.0.0.1:10049")
        .map_err(|e| {
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