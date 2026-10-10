# Test fixtures

`sso_test_rsa_key.der.b64` and `sso_test_rsa_modulus.txt` are a throwaway
2048-bit RSA key pair used only by `tests/sso_login.rs`, where a fake identity
provider signs ID tokens with it (RS256 is what most real providers use, and
the test suite cannot generate an RSA key without adding a dependency).

**It is not a secret and protects nothing.** It was generated for these tests,
has never been used anywhere else, and must never be.
