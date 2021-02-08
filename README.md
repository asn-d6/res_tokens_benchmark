This repository serves as a benchmark for the Res tokens introduced by the Tor
proposal "Res tokens: Anonymous Credentials for Onion Service DoS Resilience".

Our goal is to benchmark the token verification procedure. Measurements can be
found at `./benches/perf.rs` while the rest of the code can be found in
`./src/main.rs`.

As of right now, **token verification takes about 0.104 ms**, while token issuance
takes about 0.614 ms.

We were fortunate to find the `rsa_fdh` crate which does all the dirty work!

