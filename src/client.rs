extern crate env_logger;
extern crate futures;
extern crate http;
extern crate openssl;
extern crate tokio;
extern crate tokio_openssl;
extern crate url;
extern crate hyper;
#[macro_use] extern crate log;

use futures::Future;
use openssl::ssl::{SslConnector, SslMethod};
use std::env;
use std::net::ToSocketAddrs;
use tokio::io::{flush, read_to_end, write_all};
use tokio::net::TcpStream;
use tokio_openssl::SslConnectorExt;
use hyper::client::conn::{
    self,
    SendRequest,
    Connection,
    Handshake,
};

use hyper::{
    Request,
    Body,
    header,
};


mod identity;
mod verifier;

pub fn main() {
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "client=debug");
    }
    env_logger::init();

    let uri = match env::args().nth(1) {
        Some(uri) => uri,
        None => {
            println!("Usage: client <url>");
            return;
        }
    };

    let url = url::Url::parse(&uri).unwrap();
    let addr = url.to_socket_addrs().unwrap().next().unwrap();

    let key: [u8; 32] = [
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a,
        0x60, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
        0x69, 0x19,
    ];

    info!("this identity: {}", identity::from_secret(&key));
    let (cert, pkey) = identity::mk_x509(&key).unwrap();

    let verifier = verifier::Verifier::new(vec![String::from(
        "oXBUPpxoaRixVSgEdtPxhUNRfUY5KDztGqjEmEmc6Pp3vX1",
    )]);

    let hello = TcpStream::connect(&addr)
        .and_then(move |socket| {
            let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
            builder.set_verify_callback(openssl::ssl::SslVerifyMode::PEER, move |ok, store| {
                verifier.verify(ok, store)
            });
            builder.set_private_key(&pkey).unwrap();
            builder.set_certificate(&cert).unwrap();
            builder.check_private_key().unwrap();
            let connector = builder.build();
            connector
                .connect_async(url.host_str().unwrap(), socket)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        })
        .and_then(|socket| {
            let pkey = socket
                .get_ref()
                .ssl()
                .peer_certificate()
                .unwrap()
                .public_key()
                .unwrap();
            let pkey = pkey.public_key_to_der().unwrap();
            let identity = identity::from_der(&pkey).unwrap();
            info!("peer identity: {}", identity);

            conn::Builder::new()
                .http2_only(true)
                .handshake::<_,hyper::Body>(socket)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        })
        .and_then(|hs|{
            let (send, con) = hs;
            tokio::spawn(con.map_err(|e| error!("{}",e)));
            Ok(send)
        })
        .and_then(|mut send|{
            info!("sending req");
            let req = Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::HOST, "hyper.rs")
                .body(Body::from("{}"))
                .unwrap();
            send.send_request(req)
                .map_err(|e|{
                    error!(">>{}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        })
        .and_then(|hs|{
            info!("got something");
            Ok(())
        })
        .map_err(|e| {
            println!("ERR = {:?}", e);
        });

    tokio::run(hello);
}
