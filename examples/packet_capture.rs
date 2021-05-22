use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use std::fs;
use std::io::Read;
use structopt::StructOpt;
use tictacacs::packet::header::Header;

/// A simple tool for logging TACACS+ packets to disk.
#[derive(Clone, Debug, StructOpt)]
struct Opt {
    #[structopt(long, default_value = "127.0.0.1")]
    addr: String,
    #[structopt(long, default_value = "10049")]
    port: u16,
    #[structopt(long, default_value = "my_shared_key")]
    secret: String,
    /// output directory where packets will be written.
    #[structopt(long)]
    out: PathBuf,
    /// De-obfuscate packet bodies when writing them to disk
    #[structopt(long)]
    deobfuscate: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Opt {
        ref addr,
        ref port,
        ref secret,
        ref out,
        deobfuscate,
    } = Opt::from_args();

    let listener = TcpListener::bind(format!("{}:{}", addr, port))?;

    let mut input_buf = vec![0u8; 2 << 15];
    for stream in listener.incoming() {
        let mut stream = stream.expect("failed to read from tcp stream");

        let unix_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        println!("Reading packet at ts {}", unix_ts.as_millis());

        let bytes_read = stream.read(&mut input_buf)?;
        println!("read {} bytes", bytes_read);

        let packet_buf = &input_buf[..bytes_read];

        // read the header to verify it's a valid tacacs packet
        let header = Header::from_reader(packet_buf).expect("failed to read error");

        let raw_body = &packet_buf[12..];

        // verify the body can be decoded
        let decoded_body = header
            .body_decoder(secret, raw_body)
            .bytes()
            .collect::<Result<Vec<_>, _>>()?;

        let encoded_header = header.to_bytes();
        assert_eq!(&packet_buf[..12], encoded_header, "header is not 1:1");

        let header_filename = format!("{}_header_{}.bin", unix_ts.as_millis(), header.packet_type);
        let body_filename = format!("{}_body_{}.bin", unix_ts.as_millis(), header.packet_type);

        println!("Writing to {} and {}", header_filename, body_filename);
        fs::write(out.join(header_filename), encoded_header)?;
        let body_to_write = if deobfuscate {
            decoded_body.as_slice()
        } else {
            raw_body
        };
        fs::write(out.join(body_filename), body_to_write)?;
    }

    Ok(())
}
