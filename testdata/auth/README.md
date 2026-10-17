# Authentication fixtures

Unit tests in `crates/auth` generate RSA-2048 and Ed25519 keys and seed an in-process TXT cache. Private keys are not checked in.

The unsigned sample below is the message those tests sign. DNS is not required.
