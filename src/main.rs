use rsa_fdh;
use rsa_fdh::blind;
use rsa::{RSAPrivateKey, RSAPublicKey};
use rand::rngs::ThreadRng;

const RSA_SIZE: usize = 1028; // in bits

pub fn issuer_setup(rng: &mut ThreadRng) -> (RSAPrivateKey, RSAPublicKey) {
    // Setup the issuer
    let signer_privkey = RSAPrivateKey::new(rng, RSA_SIZE);
    let signer_privkey = signer_privkey.unwrap(); // XXX yolo error handling
    let signer_pubkey: RSAPublicKey = signer_privkey.clone().into();

    return (signer_privkey, signer_pubkey)
}

pub fn alice_blind(digest: &[u8], signer_pubkey: &RSAPublicKey, rng: &mut ThreadRng) -> (Vec<u8>, Vec<u8>) {
    return blind::blind(rng, signer_pubkey, &digest);
}

pub fn issuer_sign(blinded_digest: &[u8], signer_privkey: &RSAPrivateKey, rng: &mut ThreadRng) -> Vec<u8> {
    let blind_signature = blind::sign(rng, &signer_privkey, &blinded_digest);
    return blind_signature.unwrap(); // XXX yolo error handling
}

pub fn alice_unblind(blind_signature: &[u8], signer_pubkey: &RSAPublicKey, unblinder: &[u8]) -> Vec<u8> {
    return blind::unblind(signer_pubkey, blind_signature, unblinder);
}

pub fn verifier_validate_signature(digest: &[u8], signature: &[u8], signer_pubkey: &RSAPublicKey) -> Result<(), rsa_fdh::Error> {
    return blind::verify(signer_pubkey, digest, signature);
}

#[allow(dead_code)]
// All the work actually happens in the benchmark in benches/perf.rs
fn main() {
}
