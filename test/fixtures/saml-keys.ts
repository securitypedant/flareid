// Throwaway SAML credentials, generated solely for the test suite.
//
// Two pairs, committed with their private halves, deliberately - same
// reasoning as test/fixtures/signing-key.ts:
//
//   TEST_SAML_IDP_*   the certificate and PKCS8 private key FlareID signs
//                     assertions with under test, bound through
//                     vitest.config.ts. Tests verify signatures against the
//                     public half, so they need both.
//   TEST_SAML_SP_*    a second, unrelated pair, standing in for a service
//                     provider's signing certificate - used to sign inbound
//                     redirect-binding AuthnRequests so the verification
//                     path has something real to check.
//
// Generated with:
//   openssl req -x509 -newkey rsa:2048 -keyout idp-key.pem -out idp-cert.pem \
//     -days 3650 -nodes -subj "/CN=flareid-test-idp"
//   openssl req -x509 -newkey rsa:2048 -keyout sp-key.pem -out sp-cert.pem \
//     -days 3650 -nodes -subj "/CN=flareid-test-sp"

export const TEST_SAML_IDP_KEY_PKCS8 = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDaTFTrmtmIhP6W
+vUzgztFvxeWa0cvKqY0RaLzd4BtKUVvjsj2sg73kKMhTCCVj3b6izj0MPybqaDH
W6qiKmFnlwYpL52xSElmpzZ2rl3yIpMLuxf2sP5eXFpExOlxooQN/n5VfFX3eLnY
+ZET5PkN3ob9JgKmQButaqsKYl25ErPl20H3+cUh3rxDyxkkoOHgS2uGkQvfb/HO
flYO21vfdxQ5CuqGm/uTlyD1WGUC37O2FLycZk/7x/Befjdbq06yLSeXPrFha/9K
nR65Bm7+/Z1+Gk13vfAB3TGNHVY7R0+cJ+3JgJZMFt8GmPNfDgjtIExAatFmgmJx
+XlNI+lPAgMBAAECggEAG18t2Lr6YsFWUOUXwMVINdcfpIdADjx5SZ2fsIp/6nAd
2j6bmT87XDRhGAg9H7O09fZmBkxsKDKNS+IFE79fpkcMCTcEvVl0hrAZxqjXc8h9
CqADgbWwt3E6ClxsbwizKTQLcDmeZ+DV4MxuMgHobqJD59MPyvvH3Kc+2hb6bH2e
CIgGpDypHh8b5vyu89iMWPS/2RlRiyIGIty/S0zbngvtSvC0OK/TNT18kXYLKTso
Mg8TFxB800Ddp3F7mG1f4TLqJ0AIzt5XKVTxOPer3Eu8lLWBVf5gEtwHgrjCGMIu
IeiuYm12ogrPeKePzZNDNom6b5ruiASdc3T+zoF0aQKBgQD1hs3aScffAnomm5c3
vAc5WmfPoyl1tgo/YhbEFLGVQRm6gG1G0lOdCy0bTnE5me0Tyj5tfY9KyGRixAWc
NDQ3ZCCeQ6g3v3myaRwTL+BeJaEuo+shgrq9AmgCL2J/4TXhDS7dGUJeLpa1m51A
2KeUEpVxOENU2/9mwyKzLhnQaQKBgQDjnDA2jzwnHVhnLHnKLt+nMuj1MXQPFW0S
ZNaITX4oCX+fsesAwwBE1F/vOTGzCqs1avrU0y6wOS1pfMcsPJKC/6SpSM2RQ+QP
/KaVMC3QDUJMqdz9Fl7tXRHDoZKf2V3GmBtHFAfq5vwOlKY6+JLzF4q3WetjVv7d
NosQV+K09wKBgQCr9IR5bBDybB62qWOn4iVBEsL/1er0iND2gTEmlMOmn5hwWP+v
iSCMLUajCDYePGKg6JT+Q+C2ZFCCJ30yYBFt9c8uaH4IxS5rOFg0S+Scq0gOjTjh
GFjGhUfot90JaOY+Puhiaw1jPsfIWzswLkx3VOibCeeGKCngg6vqx8/GeQKBgFti
lXUCc2tc++aI0+lago+2ABSaI3f+6UkOVZhqTLG0hppOrAUlRhFcl5wMAalaKj2L
U2Rp2gAFJPeKkslvFIAmNi2FvouJj6LflN6ndm1nNWxkcwbmmXyB9qTuVVl6w4z9
+03BfCBTV3ZfNpLMxOt3U0mkf77l6fRVduY78xknAoGBAKE9UP2+xVnL8syrTU29
UMm5EeeY6c93J37oV3cmX7w5wB7vV1EVA9yscNEEZOpHZEwXd4e4UmHk+/rbk/uy
9wPn/DSmjpZPj1BX+nUZ8JmRwVtBiM/Tax4nYxcOJZvdjnjHnx2VeCthH7haWlEr
LZ3d5Kjsjlp15g/LjsN4VHiB
-----END PRIVATE KEY-----
`;

export const TEST_SAML_IDP_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIC9jCCAd6gAwIBAgIUHjiHOlDAtpT9RLx0XzpC4Jn2xKwwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQZmxhcmVpZC10ZXN0LWlkcDAeFw0yNjEwMzEwNzQ1NTRa
Fw0zNjEwMjgwNzQ1NTRaMBsxGTAXBgNVBAMMEGZsYXJlaWQtdGVzdC1pZHAwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaTFTrmtmIhP6W+vUzgztFvxeW
a0cvKqY0RaLzd4BtKUVvjsj2sg73kKMhTCCVj3b6izj0MPybqaDHW6qiKmFnlwYp
L52xSElmpzZ2rl3yIpMLuxf2sP5eXFpExOlxooQN/n5VfFX3eLnY+ZET5PkN3ob9
JgKmQButaqsKYl25ErPl20H3+cUh3rxDyxkkoOHgS2uGkQvfb/HOflYO21vfdxQ5
CuqGm/uTlyD1WGUC37O2FLycZk/7x/Befjdbq06yLSeXPrFha/9KnR65Bm7+/Z1+
Gk13vfAB3TGNHVY7R0+cJ+3JgJZMFt8GmPNfDgjtIExAatFmgmJx+XlNI+lPAgMB
AAGjMjAwMB0GA1UdDgQWBBR/OsYanfDARlwZyJ7gmaKekTjbMTAPBgNVHRMBAf8E
BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQC762recsct0sNF2GfWttWAU9enY3hk
MBeszvdo4QVOdS7jKr0ZrgFF1QsaAfesAMPQTxkgvuMPzSm0yuJP1dHr/nlsKKdJ
xy9aJ/JDSNDhcdHoaRU8CJzjFU9Fhxxo8k9uHr0VXSknLSGHD59cw9qymQM2bedQ
WQRXcBwioS/BlY2Y9sN35zPngCfDyZXOW70GjoF/bhXujnUgUFF7ezLuea4aISax
ujVJieRKq+ENcV7jJ/jb2GtrhUsK2drcwefMYcfNmEVhRCtrH38yA9wVTcHV4Ecy
USY5Bp2Dq3veSylk6F8azTJNwF0JsJUxSlZqcGEvYRXl9Tgcg2cYsLHj
-----END CERTIFICATE-----
`;

export const TEST_SAML_SP_KEY_PKCS8 = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCgN7wr2OwJijal
oCR7milNvBtR5+tRi7SNkmFj0ol82lmI1cQWDAb3huNJe4Q3pXZ4c2zUJ1chSViC
SIt+H/r5Bh6yOru8E8V8LyGvJReDRUppTLB7HnYnrWq8ZwOTyW3E8fva1dCOjhm0
Tmy1axigL4b9BikBbfvdneGDZ/VtshZ1/XWnjeRpsPoUMO7LNsJRxGLityBuYlCM
viRHaFwAELA1G5zjqyP0orduafDuhS880dkAWzBmGpa7DjUsYdkpK+sPLqgAmhYq
ZvUqNIs4TIR/GCQ+hyEFTYPOVRJy5l/qn5IhhLIQfQOftM7Q1z/nLyAsRp0Ln4Yo
8AUb0WedAgMBAAECggEACF5g6dMCB6ci65ianAou/IYS0NhrjKFFF3ZjhLJ+k/lW
+LRejBHcwbK+AU/LIpnCvzZOo1ZBHgmV7r6Zt3po9ZD1EYIxd18UNarDxUFx7pCa
YZ2r3Wjd6xY+OQRFRfbp6oIC3o9eJKDiuG3p2uzZJtgH4p3rwZnCsI5XaGTwIOag
CMLSF5U27ikIcdcrXWcSbNau2KHfAgC9GT1s4GVU71SWp+ZZ859utHFZo2tmDEll
1zlAPtoO16+kXDlGZJ+XKSCdXIPlEDOq1MD7RMxL6KjEUALNimp4MrFZ4cOulMdn
hcT8jMnbiBd7hkDXfaMMD3MIOf63SB3QWPFlxsVlUQKBgQDcRYwdH+Kteccmvp/6
+vgpsNPiE9s6EeMdw5bQnwKxJaDFPX5WlLrxygh/ddsm50xht3NkocPWR36wHkc6
J7D/pq8sDfKla7v9CX+omoMzsLVcqS41dikfmTLk+bCAhSUvnWln9CMvBJewUxOi
F7aIRqp1G/ly0SWb+zVlk+z17wKBgQC6NIlsF9gTkPh3w3AEZxDXZNmc6wswrQsF
hzcFzmbTAe3D3Rhwk/6t9TuJRzZvO/iRpb5WVCDyfQKAMtIm6LkP5g5rGkSRJGXb
tudqwrKqQkKbbFNKtJ+erjd5U0yogkbCjQJM+8ihO6bVtlEONJm9e5zsI3cgvlAe
6160dSsnMwKBgBQ+VAUtNADrazEVXdCMFhiGxsJFPuWUVUIcApVDt9Sd96uI3j6I
xrGH9sX4B98IbM2iNXmvIDdmNK9s6PDgSvUD1Z9/3Kf1Qb6ci93r7VjnyZMtfTCu
nlLoGnROujjlg6hfmBtUpZMhoeszh19jPIRDslC29HLn48P1D1A5ixKDAoGAKeB0
44V9R/E7oBupDqRrSjXZJwxJaPoR131wZ3Li9yOg6ILJ40+1YEQdzqLgYCXZok/n
PZ0QB9kLfe9wCeYe8K9poLa4ovfPnJlG9GCzM81RE4lKNivnFhXSTgvo2qDp7wkt
ckjR90jmHXwyQIKd7NpnEUhsm0WR2VJP6z/Ko7cCgYBDX8McveON4AJJeIDmoMgS
1h8xPAlVGiMmsrX8ZTHwy+IFwfZHQ++EaZjLPJb5K2SxK4nnkMWySurw4fv5FU4V
nzFP4yTq6oyr3PNhON0Pr6niuHA4SeQVjGHP55ev5hSdX7lB6vfGQ/e6ZfuWIqJ9
aNci3iqngpDgSTWIIJTCEg==
-----END PRIVATE KEY-----
`;

export const TEST_SAML_SP_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIC9DCCAdygAwIBAgIUdUpHr2O4i8Wghh2CJaMzZlyV8TwwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPZmxhcmVpZC10ZXN0LXNwMB4XDTI2MTAzMTA3NDU1NFoX
DTM2MTAyODA3NDU1NFowGjEYMBYGA1UEAwwPZmxhcmVpZC10ZXN0LXNwMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoDe8K9jsCYo2paAke5opTbwbUefr
UYu0jZJhY9KJfNpZiNXEFgwG94bjSXuEN6V2eHNs1CdXIUlYgkiLfh/6+QYesjq7
vBPFfC8hryUXg0VKaUywex52J61qvGcDk8ltxPH72tXQjo4ZtE5stWsYoC+G/QYp
AW373Z3hg2f1bbIWdf11p43kabD6FDDuyzbCUcRi4rcgbmJQjL4kR2hcABCwNRuc
46sj9KK3bmnw7oUvPNHZAFswZhqWuw41LGHZKSvrDy6oAJoWKmb1KjSLOEyEfxgk
PochBU2DzlUScuZf6p+SIYSyEH0Dn7TO0Nc/5y8gLEadC5+GKPAFG9FnnQIDAQAB
ozIwMDAdBgNVHQ4EFgQU7i4uT6zq3UZW+ETQt7nx/riribEwDwYDVR0TAQH/BAUw
AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAVdfmKHWmvM+IMAIPZxsKEzRdTYDqEelu
jCJ0u6xAgQd1Zkj182c0tRM+JcMRqPwQIFA8rXbiVNgefQOan6lbodBJc61g/oyU
rOoo3ndQHlSYUjPFBFupg5ji1dHQEETfmHAt93rJbFPenIRnbUlMHizH5fwFxCk2
oZ3DDNzzW+ae1TWBoOBNVD+2PaCC1e/ilGb9OdEDzSj+GAw+mKORHPrefIEf5nAG
Utpqrmu+gHvektUHjX9PSFB7GZy232jZ8dgXED+tymzo3qeeZrXWTQhVhp/iYiof
tXzXJ9CnN8rmcPsfijGSFJK3N9Du6E7gRNqRSvxq56V61MP2ZbIc7g==
-----END CERTIFICATE-----
`;
