# Threshold Ed25519

The threshold-ed25519 go module contains primatives for implementing threshold signatures for ed25519 curves.

Threshold signatures allow for splitting a private key into `m` secret shares. To sign a message, at least some threshold of the shareholders need to coordinate and provide their individual signatures using their share. These individual signatures combine to form a single valid signature.

## References

- [Provably Secure Distributed Schnorr Signatures
  and a (t, n) Threshold Scheme for Implicit
  Certificates](http://cacr.uwaterloo.ca/techreports/2001/corr2001-13.ps)
