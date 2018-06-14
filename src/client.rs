extern crate env_logger;
extern crate futures;
extern crate hyper;
extern crate tokio;
extern crate url;
#[macro_use]
extern crate log;
extern crate x0;

use futures::Future;
use futures::Stream;
use hyper::{Body, Request};
use std::env;
use std::io::Write;

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

    let client = x0::client::builder()
        .verifier(verifier)
        .url(uri.clone())
        .identity(identity)
        .build();

    let hello = client
        .and_then(|(identity, client)| {
            info!("peer identity: {}", identity.public_id());

            let request = Request::builder()
                .method("POST")
                .uri(uri)
                .body(Body::from("look at my data, my data is amazing"))
                .unwrap();

            client
                .request(request)
                .and_then(|res| {
                    println!("Response: {}", res.status());
                    println!("Headers: {:#?}", res.headers());
                    res.into_body().for_each(|chunk| {
                        std::io::stdout()
                            .write_all(&chunk)
                            .map_err(|e| panic!("example expects stdout is open, error={}", e))
                    })
                })
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        })
        .map_err(|err| {
            error!("Error {}", err);
        });

    tokio::run(hello);
}
