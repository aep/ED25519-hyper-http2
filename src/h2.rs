extern crate futures;
#[macro_use]
extern crate log;
extern crate bytes;
extern crate env_logger;
extern crate h2;
extern crate http;
extern crate openssl;
extern crate tokio;
extern crate tokio_openssl;

use bytes::{Buf, Bytes, IntoBuf};
use futures::{future, Future, Stream};
use h2::server;
use http::{Response, StatusCode};
use openssl::ssl::{SslAcceptor, SslMethod};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_openssl::SslAcceptorExt;
use futures::IntoFuture;

mod identity;
mod verifier;


fn handle_request(
    identity: String,
    req: http::Request<h2::RecvStream>,
    mut resp: h2::server::SendResponse<bytes::Bytes>,
) -> impl Future<Item=(), Error=h2::Error> {
    info!("[{}] H2 sending response", identity);
    let response = Response::builder().status(StatusCode::OK).body(()).unwrap();

    let identity_ = identity.clone();

    resp.send_response(response, false)
        .into_future()
        .and_then(|mut send| {
            req.into_body()
                .fold(send, move |mut send, frame| {
                    info!("[{}] H2 recv frame {}", identity_, frame.len());
                    if let Err(e) = send.send_data(frame, false) {
                        error!(" -> err={:?}", e);
                    }
                    future::ok::<_, h2::Error>(send)
                })
                .and_then(move |mut send| {
                    info!("[{}] H2 closing", identity);
                    // close send stream when recv closed
                    if let Err(e) = send.send_data(Bytes::new(), true) {
                        error!(" -> err={:?}", e);
                    }
                    Ok(())
                })
        })
}

fn main() {
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "server=debug");
    }
    env_logger::init();

    // this is the private key, which could be loaded from whatever static storage
    let key: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    info!("this identity: {}", identity::from_secret(&key));
    let (cert, pkey) = identity::mk_x509(&key).unwrap();

    // slap the keys into an acceptor
    let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&pkey).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    acceptor.check_private_key().unwrap();
    let verifier = verifier::Verifier::new_trust_all();
    acceptor.set_verify_callback(
        openssl::ssl::SslVerifyMode::PEER | openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        move |ok, store| verifier.verify(ok, store),
    );
    let acceptor = Arc::new(acceptor.build());

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3000);
    info!("listening on {}", addr);
    let tcp = TcpListener::bind(&addr).unwrap();

    // for each incomming connection
    let server = tcp.incoming()
        .for_each(move |conn| {
//            let acceptor = acceptor.clone();
//            // build up TLS
//            let acceptor = acceptor
//                .accept_async(tcp)
//                .and_then(|conn| {
//                    let pkey = conn.get_ref()
//                        .ssl()
//                        .peer_certificate()
//                        .unwrap()
//                        .public_key()
//                        .unwrap();
//                    let pkey = pkey.public_key_to_der().unwrap();
//                    let identity = match identity::from_der(&pkey) {
//                        None => return Ok(()),
//                        Some(i) => i,
//                    };
//                    info!("[{}] TLS bound", identity);
                    let identity = String::from("null");

                    let connection = server::handshake(conn)
                        .and_then(move |conn| {
                            info!("[{}] H2 connection bound", identity);
                            conn.for_each(move |(request, mut respond)| {
                                let identity_ = identity.clone();
                                tokio::spawn(handle_request(identity.clone(), request, respond)
                                             .map_err(move |e| error!("[{}] {}", identity_, e)));
                                future::ok(())
                            })
                        })
                        .map_err(|err| {
                            error!("h2 error {:?}", err);
                        });

                    tokio::spawn(connection);
                    Ok(())
//                })
//                .map_err(|err| {
//                    error!("TLS error {:?}", err);
//                });
//            tokio::spawn(acceptor);
//            Ok(())
        })
        .map_err(|err| {
            error!("srv error {:?}", err);
        });

    tokio::run(server);
}
