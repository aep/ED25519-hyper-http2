extern crate env_logger;
extern crate futures;
extern crate hyper;
extern crate openssl;
extern crate tokio;
extern crate tokio_openssl;
#[macro_use]
extern crate log;
extern crate x0;

use futures::{future, Future, Stream};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Chunk, Method, Request, Response, StatusCode};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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

    let identity = x0::Identity::from_private(key.to_vec());
    info!("this identity: {}", identity.public_id());

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3000);

    let verifier = x0::Verifier::new_trust_all();

    let server = x0::server::builder()
        .identity(identity)
        .verifier(verifier)
        .bind(addr)
        .unwrap();

    info!("listening on {}", addr);

    let server = server
        .for_each(|maybe|{
            let (identity, conn) = match maybe {
                Err(e) => {warn!("{}", e); return Ok(())},
                Ok(v)  => v,
            };
            info!("[{}] connected", identity.public_id());
            let svc = service_fn(|req| serve(req));
            let mut http = Http::new();
            http.http2_only(true);
            let conn = http.serve_connection(conn, svc)
                .map_err(|err| error!("srv io error {:?}", err));
            tokio::spawn(conn);
            Ok(())
        })
        .map_err(|e| {error!("srv error {}", e);});


    tokio::run(server);
}
