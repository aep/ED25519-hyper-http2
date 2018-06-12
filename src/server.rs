extern crate hyper;
extern crate futures;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate tokio;
extern crate openssl;
extern crate openssl_sys;
extern crate tokio_openssl;

use futures::{future, Future, Stream};
use hyper::service::service_fn;
use hyper::{Body, Chunk, Client, Method, Request, Response, Server, StatusCode};

static TEXT: &str = "Hello, World!";
static NOTFOUND: &[u8] = b"Not Found";

fn serve(req: Request<Body>) -> Box<Future<Item=Response<Body>, Error=hyper::Error> + Send> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/") => {
            let body = Body::from(TEXT);
            Box::new(future::ok(Response::new(body)))
        },
        _ => {
            let body = Body::from(NOTFOUND);
            Box::new(future::ok(Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(body)
                                .unwrap()))
        }
    }
}

use std::net::{
    SocketAddr,
    IpAddr,
    Ipv4Addr,
};

use std::sync::Arc;
use tokio::io;
use tokio::net::TcpListener;
use tokio::io::AsyncRead;
use std::env;
use tokio_openssl::{SslAcceptorExt};
use openssl::ssl::{SslAcceptor, SslMethod};
use std::fs::File;
use openssl::{
    x509::X509,
    pkey::PKey,
};
use hyper::server::conn::Http;


fn main() {
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "debug");
    }
    env_logger::init();

    let key: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60 ];
    let (cert, pkey) = mk_x509(&key).unwrap();

    let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&pkey).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = Arc::new(acceptor.build());

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3000);
    info!("listening on {}", addr);
    let tcp = TcpListener::bind(&addr).unwrap();
    let server = tcp.incoming().for_each(move |tcp| {
        let acceptor = acceptor.clone();
        let acceptor = acceptor.accept_async(tcp).and_then(|conn|{
            let svc = service_fn(|req|{
                serve(req)
            });
            let http = Http::new();
            let conn = http.serve_connection(conn, svc)
                .map_err(|err| {
                    println!("srv io error {:?}", err)
                });
            tokio::spawn(conn);
            Ok(())
        })
        .map_err(|err| {
            println!("TLS error {:?}", err);
        });
        tokio::spawn(acceptor);
        Ok(())
    })
    .map_err(|err| {
        println!("srv error {:?}", err);
    });

    tokio::run(server);
}

fn cvt_p<T>(r: *mut T) -> Result<*mut T, openssl::error::ErrorStack> {
    use openssl::error::ErrorStack;
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn mk_x509(key: &[u8]) -> Result<(openssl::x509::X509, openssl::pkey::PKey<openssl::pkey::Private>), openssl::error::ErrorStack> {
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        pkey::{PKey, PKeyRef, Private},
        rsa::Rsa,
        nid::Nid,
        ec::{EcKey, EcGroup},
        x509::{X509, X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509VerifyResult},
        x509::extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier},
    };

    // header copied from 'openssl genpkey -algorithm ed25519'
    let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

    der.extend_from_slice(&key);

    let privkey = PKey::private_key_from_der(&der)?;


    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "TX")?;
    x509_name.append_entry_by_text("O", "organization")?;
    x509_name.append_entry_by_text("CN", "localhost")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&privkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(1)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
//    cert_builder.append_extension(KeyUsage::new()
//                                  .critical()
//                                  .key_cert_sign()
//                                  .crl_sign()
//                                  .build()?)?;
//
    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&privkey, unsafe{MessageDigest::from_ptr(std::ptr::null_mut())})?;
    let cert = cert_builder.build();

    Ok((cert, privkey))
}
