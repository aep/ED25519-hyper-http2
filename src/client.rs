extern crate env_logger;
extern crate futures;
extern crate hyper;
extern crate tokio;
extern crate url;
#[macro_use]
extern crate log;
extern crate x0;
extern crate prost;
#[macro_use] extern crate prost_derive;
extern crate tower_h2;
extern crate tower_grpc;
extern crate tower_http;

use futures::Future;
use futures::Stream;
use std::env;
use std::io::Write;
use tower_h2::client::Connection;
use tokio::{runtime};
use tower_grpc::{Request, Response};

pub mod zeroxproto {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/zeroxproto.v1.rs"));
    }
}

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

    let key: [u8; 32] = [
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a,
        0x60, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
        0x69, 0x19,
    ];
    let identity = x0::Identity::from_private(key.to_vec());
    info!("this identity: {}", identity.public_id());

    let verifier = x0::Verifier::new(vec![String::from(
            "oXBUPpxoaRixVSgEdtPxhUNRfUY5KDztGqjEmEmc6Pp3vX1",
            )]);

    let mut rt = runtime::Runtime::new().unwrap();
    let executor = rt.executor();

    let client = x0::client::builder()
        .verifier(verifier)
        .url(uri.clone())
        .identity(identity)
        .build();

    let hello = client
        .and_then(|(identity, conn)| {
            info!("peer identity: {}", identity.public_id());
            Connection::handshake(conn, executor)
                .map_err(|_| panic!("failed HTTP/2.0 handshake"))
        })
    .map(move |conn| {
        use zeroxproto::v1::client::Bearer;
        use tower_http::add_origin;

        let conn = add_origin::Builder::new()
            .uri(uri)
            .build(conn)
            .unwrap();

        Bearer::new(conn)
    })
    .and_then(|mut client| {
        use zeroxproto::v1::Empty;
        client.get_identity(Request::new(Empty{}))
            .map_err(|e| panic!("gRPC request failed; err={:?}", e))
    })
    .and_then(|response| {
        println!("RESPONSE = {:?}", response);
        Ok(())
    });

    rt.block_on(hello).unwrap();
}
