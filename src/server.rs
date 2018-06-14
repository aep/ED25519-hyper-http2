extern crate futures;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate openssl;
extern crate tokio;
extern crate tokio_openssl;

use futures::{future, Future, Stream};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Chunk, Client, Method, Request, Response, Server, StatusCode};
use openssl::ssl::{SslAcceptor, SslMethod};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_openssl::SslAcceptorExt;

mod identity;
mod verifier;

// just the http handler. boring, skip this
static TEXT: &str = "Hello, World!";
static NOTFOUND: &[u8] = b"Not Found";
fn serve(req: Request<Body>) -> Box<Future<Item = Response<Body>, Error = hyper::Error> + Send> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/") => {
            let body = req.into_body().map(|i| {
                info!("got data {}", i.len());
                i
            });
            Box::new(future::ok(Response::new(Body::wrap_stream(body))))
        }
        _ => {
            let body = Body::from(NOTFOUND);
            Box::new(future::ok(
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(body)
                    .unwrap(),
            ))
        }
    }
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
            //  let acceptor = acceptor.clone();
            //  // build up TLS
            //  let acceptor = acceptor.accept_async(tcp).and_then(|conn|{
            //      let pkey = conn.get_ref().ssl().peer_certificate().unwrap().public_key().unwrap();
            //      let pkey = pkey.public_key_to_der().unwrap();
            //      let identity = match identity::from_der(&pkey) {
            //          None => return Ok(()),
            //          Some(i) => i,
            //      };
            //      info!("peer identity: {}", identity);

            let svc = service_fn(|req| serve(req));
            let mut http = Http::new();
            http.http2_only(true);
            // build up http
            let conn = http.serve_connection(conn, svc)
                .map_err(|err| error!("srv io error {:?}", err));
            tokio::spawn(conn);
            Ok(())
            //  })
            //  .map_err(|err|{error!("TLS error {:?}", err);});
            //  tokio::spawn(acceptor);
            //  Ok(())
        })
        .map_err(|err| {
            error!("srv error {:?}", err);
        });

    tokio::run(server);
}
