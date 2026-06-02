// Certificate fixtures for the TLS tests.
//
// Both were generated locally with openssl and are self-contained: no
// certificate captured from a real device is committed here.
//
// * `SELF_SIGNED_CERT_DER_BASE64` — `openssl req -x509`, CN=netgap-test.local,
//   valid 2026-10-01 to 2036-09-28.
// * `CA_SIGNED_CERT_DER_BASE64` — `openssl x509 -req` against a local CA,
//   CN=device.lan issued by CN=Netgap Test CA, valid 2026-10-01 to 2027-10-01.
//
// Regenerate with `openssl` if the parser ever needs different shapes; the
// tests assert the values above, so they will fail loudly if the files change.

const SELF_SIGNED_CERT_DER_BASE64: &str = concat!(
        "MIID4DCCAsigAwIBAgIUcnzDZgRz8m5Q8fLPRFp5mhd82CowDQYJKoZIhvcNAQELBQAwZTELMAkG",
        "A1UEBhMCTlAxEDAOBgNVBAgMB0JhZ21hdGkxEjAQBgNVBAcMCUthdGhtYW5kdTEUMBIGA1UECgwL",
        "TmV0Z2FwIFRlc3QxGjAYBgNVBAMMEW5ldGdhcC10ZXN0LmxvY2FsMB4XDTI2MTAwMTA2NDgzM1oX",
        "DTM2MDkyODA2NDgzM1owZTELMAkGA1UEBhMCTlAxEDAOBgNVBAgMB0JhZ21hdGkxEjAQBgNVBAcM",
        "CUthdGhtYW5kdTEUMBIGA1UECgwLTmV0Z2FwIFRlc3QxGjAYBgNVBAMMEW5ldGdhcC10ZXN0Lmxv",
        "Y2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw5Qj3/kOqoeGFo+NTxSYjp2DxE7i",
        "Z8+ff2Cw3MDOQjG9TRQ/q8KRZi8tGsFns4c0UhMQtqqtcmfh6mjGlR0DqZl6K4XeOQPkTuFPyTza",
        "SgZGDuezwe/C973o56gCAryxG5KMrAz2jRJv/ipyIYo3l+zISqF6mItF7/j581Im+ej0WerKDJpO",
        "XfMRY6LBqBuMbv/lDnbSOtuw7Shm0mVwklXyoO+C7CnAGu8Idy8O9VeLFSCO/B1ta0xNpUzUJ5Kx",
        "IDLGWXNzLLeBiMPJOgdv1Z8MzAOpN0E6e8pS98XFBCge2jQUllHK+4FVBF3+ZPLLxJfIp0d4t9DS",
        "ZSvT/GAl/wIDAQABo4GHMIGEMB0GA1UdDgQWBBSxRqVjqlVLuOpbYnWVyI2PDyWusDAfBgNVHSME",
        "GDAWgBSxRqVjqlVLuOpbYnWVyI2PDyWusDAPBgNVHRMBAf8EBTADAQH/MDEGA1UdEQQqMCiCEW5l",
        "dGdhcC10ZXN0LmxvY2FsghMqLm5ldGdhcC10ZXN0LmxvY2FsMA0GCSqGSIb3DQEBCwUAA4IBAQBg",
        "LY65yWSpxenGblf+41ZZcDM0SWnNcQ49o9gP72sP6zz58Y0p60i0jP+AfHUNsACGhbtQkEtb8+UG",
        "MzPikBcM7D0012W1ntQGAWhBYJ/WVDXpSCst9ssEwe6SwY6p078oSRKf2MCrzhcdWF4OoYYL7k1N",
        "Rcp4POfjH8tISRhEudGIpegpK/YKtgp4QpIPmHWsOzQqQMg0uoQ0Nn5L6Va+szKSxMgPKYBHFR7l",
        "oNAYi6JpOCgyNM/eId0Uue1njWHLNyGT7JgYg5uYnyf9mO0WGRKKbhgRsL5BFaho53V55TdiSFzt",
        "9STc/EVnO4DDI2LIYmCMPJFzQNXcBZ4PKYEj",
);

const CA_SIGNED_CERT_DER_BASE64: &str = concat!(
        "MIIDKjCCAhKgAwIBAgIUWvUo/2pth+U5aZy/LEJsfRa+dWwwDQYJKoZIhvcNAQELBQAwLzEXMBUG",
        "A1UEAwwOTmV0Z2FwIFRlc3QgQ0ExFDASBgNVBAoMC05ldGdhcCBUZXN0MB4XDTI2MTAwMTA2NDg1",
        "MloXDTI3MTAwMTA2NDg1MlowKzETMBEGA1UEAwwKZGV2aWNlLmxhbjEUMBIGA1UECgwLTmV0Z2Fw",
        "IFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDfam+cIhBuX/XUIYgWG1hUsjw0",
        "Ha95EEabY7pPDkW1xAfEv4aujl1tpATyK8Q3t/ErQAO9HsRlIEi//XeKy4cKkQ2k9ioYvcP/Z3Dv",
        "09Pj331ngeIbrOqWOJYdiEMFRXfNyeQ2w2AYwn2N4PBIuxMw7nrmZiVQDT0vnDkfLuikHYWRfgSU",
        "KEFvgMB1m5WAGS5TOjfKTMB8x8+x4Ug2ovTeVuq6jygnSz3kg5blC/oFWJTA8+62A1Iz1DKm7P/z",
        "Xo7xs8Z98gVlN2UpQY1FpMqL9hSRKM6mNKu7MoMLZIskZnwkaMSvBhaRgoV2PvRI6uNgAvxzqgb/",
        "PwVTBbIQ8hjJAgMBAAGjQjBAMB0GA1UdDgQWBBR+0UDRuHSFmb7b9Nk2mCsEuOyiWzAfBgNVHSME",
        "GDAWgBSOUB6FfsrjDvDkPDAio2aEK4KL+zANBgkqhkiG9w0BAQsFAAOCAQEAp/Y26lXymw8lFFia",
        "qPyg+a8KjAvWAQBOZ2HnkJpNkvIVYiHggkoxtIW7x5JGYK0v/pA88QYuHBHRa8BC5BXmJgYkDF1V",
        "5hby1KidzzQnqATga366AH2KOp7/9GDjY1UD9S0IZ4cLM1Bb/e0JIU1sbLqIdcjRSWsuxeaUM+Bv",
        "iVUAhe6nT5ESQ23tSzDMddoeAcV6ynMHQ90D/BmAgjFNdRqQUX0Bx97p7REmP1HMZNW5PRJKhltM",
        "UFvMLo1fgUbCi0s2cb9xyHs7g4TwCTmCkxT8N2K6cEKmHTsZa4xGcHWMzateJXMeihQZq1wWuWE/",
        "JsKCTQKz82FGn0TVPtrf7Q==",
);
