# TLS identity test fixtures

`localhost.der` / `localhost.pem` are the same self-signed RSA certificate,
generated for this repository's loopback tests with .NET CertificateRequest.
It contains SAN DNS:localhost and is valid from 2026-01-01 to 2036-01-01.
`localhost-key.der` is its PKCS#8 private key, deliberately public test data.
Never use this identity or trust root in a deployment.

Tests use fixed Unix times inside and outside the validity interval and test
an unrelated hostname. No OpenSSL installation or external server is required
to execute the tests.
