# Signing keys

FlareID signs every ID token and access token with a private key. Applications check the signature with the public keys published at `/jwks.json`.

FlareID generates the keys itself and stores them encrypted with the `KEY_ENCRYPTION_KEY` secret. There is one active key per algorithm: **RS256** (the default, supported everywhere) and **ES256**. Each [OIDC client](oidc.md#settings) chooses which one signs its ID tokens.

## Rotate a key

Rotate a key on a schedule, or straight away if you think it's been exposed.

1. Go to **Security → Signing keys**.
2. Select **Rotate** next to the algorithm.

The new key signs every token from then on, with no redeploy. The old key stays published for a while, so tokens it already signed still verify. Applications that cache the key set pick up the new key on their next refresh.

## SAML certificate

SAML responses are signed with a separate certificate, set with the `SAML_SIGNING_CERT` and `SAML_SIGNING_KEY_PKCS8` secrets. Its expiry date is shown on every [SAML app](saml.md)'s page. To replace it, run `npm run saml:keygen`, set the new secrets, and update the certificate in each SAML app.
