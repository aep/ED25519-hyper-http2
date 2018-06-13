use identity;
use openssl;

pub struct Verifier {
    trusted: Option<Vec<String>>,
}

impl Verifier {
    pub fn new_trust_all() -> Self {
        Self { trusted: None }
    }

    pub fn new(trusted: Vec<String>) -> Self {
        Self {
            trusted: Some(trusted),
        }
    }

    pub fn verify(&self, _ok: bool, store: &mut openssl::x509::X509StoreContextRef) -> bool {
        let pkey = match store.current_cert() {
            None => {
                warn!("connection has no current_cert");
                return false;
            }
            Some(v) => v,
        };
        let pkey = match pkey.public_key() {
            Err(e) => {
                warn!("{}", e);
                return false;
            }
            Ok(v) => v,
        };
        let pkey = match pkey.public_key_to_der() {
            Err(e) => {
                warn!("{}", e);
                return false;
            }
            Ok(v) => v,
        };
        let identity = match identity::from_der(&pkey) {
            None => return false,
            Some(v) => v,
        };

        match &self.trusted {
            Some(trusted) => {
                for tid in trusted {
                    if ct_compare(&identity, tid) {
                        return true;
                    }
                }
                warn!("remote identity {} not trusted", identity);
                return false;
            }
            None => true,
        }
    }
}

fn ct_compare(a: &str, b: &str) -> bool {
    debug_assert!(a.len() == b.len());
    a.bytes()
        .zip(b.bytes())
        .fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
}
