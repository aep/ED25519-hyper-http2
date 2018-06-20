extern crate env_logger;
extern crate futures;
extern crate hyper;
extern crate openssl;
extern crate tokio;
extern crate tokio_openssl;
#[macro_use] extern crate log;
extern crate prost;
#[macro_use] extern crate prost_derive;
extern crate x0;
extern crate tower_h2;
extern crate tower_grpc;
extern crate http;

use futures::{future, Future, Stream};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tower_grpc::{Request, Response};
use tokio::{runtime};


pub mod zeroxproto {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/zeroxproto.v1.rs"));
    }
}


#[derive(Clone)]
struct Bearer {
}

impl Bearer {
    pub fn new() -> Self {
        Self {
        }
    }
}

impl zeroxproto::v1::server::Bearer for Bearer {
    type GetIdentityFuture  = future::FutureResult<Response<zeroxproto::v1::IdentityReply>, tower_grpc::Error>;

    fn get_identity(&mut self, request: Request<zeroxproto::v1::Empty>) -> Self::GetIdentityFuture {

        let identity = String::from_utf8(
            request.headers().get("Y-0X-VERIFIED-IDENTITY").unwrap().as_bytes().to_vec()
            ).unwrap();

        let response = Response::new(zeroxproto::v1::IdentityReply {
            version:  1,
            id: identity,
        });
        future::ok(response)
    }
}


fn main() {
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "server=debug");
    }
    env_logger::init();

    let rt = runtime::Runtime::new().unwrap();
    let executor = rt.executor();


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

    let new_service = zeroxproto::v1::server::BearerServer::new(Bearer::new());

    let h2 = tower_h2::Server::new(new_service, Default::default(), executor);

    let server = server
        .for_each(move |maybe|{
            let (identity, conn) = match maybe {
                Err(e) => {warn!("{}", e); return Ok(())},
                Ok(v)  => v,
            };
            let identity = identity.public_id();

            info!("[{}] connected", identity);

            let identity_ = identity.clone();
            let set_identity = move |request: &mut http::Request<()>| {
                request.headers_mut().insert("Y-0X-VERIFIED-IDENTITY",
                    hyper::header::HeaderValue::from_str(&identity_).unwrap());
            };

            let identity_ = identity.clone();
            let conn = h2.serve_modified(conn, set_identity)
                .map_err(move |e| error!("[{}] h2 error: {:?}", identity_, e));
            tokio::spawn(conn);
            Ok(())
        })
        .map_err(|e| error!("srv error {}", e));


    tokio::run(server);
}
