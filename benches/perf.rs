use std::time::Duration;

use rsa_fdh;
use rsa_fdh::blind;
use sha2::{Sha256};

use criterion::*;

#[path = "../src/main.rs"]
mod main;
use crate::main::*;

fn benchmark_blind_rsa(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    // 0) Set up the Token Issuer
    let (signer_privkey, signer_pubkey) = issuer_setup(&mut rng);

    // Our protocol has four phases:
    // 1) Alice creates the message digest and blinds it
    let digest_body = b"facebook2g46irvua2l3oavwi55nwp4sfwxxk6uiba2kpwatrapd7xyd.onion";
    let dest_digest = blind::hash_message::<Sha256, _>(&signer_pubkey, digest_body).unwrap();
    let (blinded_message, unblinder) = alice_blind(&dest_digest, &signer_pubkey, &mut rng);

    // 2) Alice sends blinded digest to the Issuer. Issuer signs and returns the blinded signature.
    let blinded_signature = issuer_sign(&blinded_message, &signer_privkey, &mut rng);

    // Benchmark the issuance while we are at it!
    c.bench_function("issuance", |b| b.iter(|| {
        issuer_sign(&blinded_message, &signer_privkey, &mut rng);
    }));

    // 3) Alice unblinds the signature and sends it to Verifier
    let signature = alice_unblind(&blinded_signature, &signer_pubkey, &unblinder);

    // 4) Verifier verifies the signature (benchmark it!)
    c.bench_function("verification", |b| b.iter(|| {
        let my_digest = blind::hash_message::<Sha256, _>(&signer_pubkey, digest_body).unwrap();
        if my_digest != dest_digest { // Verify received digest
            panic!("check failed");
        }
        let result = verifier_validate_signature(&dest_digest, &signature, &signer_pubkey);
        result.unwrap(); // panic on failed verification
    }));
}

criterion_group!{name = benches;
                 // Each measurement should take one minute
                 config = Criterion::default().measurement_time(Duration::from_secs(60));
                 targets = benchmark_blind_rsa
                }
criterion_main!(benches);
