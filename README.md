# Threshold Ed25519

The threshold-ed25519 go module contains primatives for implementing threshold signatures for ed25519 curves.

Threshold signatures allow for splitting a private key into `m` secret shares. To sign a message, at least some threshold of the shareholders need to coordinate and provide their individual signatures using their share. These individual signatures combine to form a single valid signature.

### Security notes
As described on https://github.com/MystenLabs/ed25519-unsafe-libs, a private key can be leaked when an invalid public key is used to create an ed25519 signature.
The fix for this is generally to require the private key and then derive the public key from the private.

This does not work for threshold signing as the cosigners do not have a complete private key, only their respective shares.
In testing the leaked value is shown to be the ephemeral public key which is not a secret. 

## References

- [Provably Secure Distributed Schnorr Signatures
  and a (t, n) Threshold Scheme for Implicit
  Certificates](http://cacr.uwaterloo.ca/techreports/2001/corr2001-13.ps)
