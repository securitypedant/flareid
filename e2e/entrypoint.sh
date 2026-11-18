#!/bin/sh
# Brings up a throwaway local FlareID: fresh secrets, local D1 migrations,
# then wrangler dev. See e2e/Dockerfile and docs/e2e.md.
set -e

cat > .dev.vars <<EOF
BOOTSTRAP_TOKEN=${BOOTSTRAP_TOKEN:-e2e-bootstrap-token}
KEY_ENCRYPTION_KEY=${KEY_ENCRYPTION_KEY:-$(head -c 48 /dev/urandom | base64)}
PASSWORD_HASHER=${PASSWORD_HASHER:-pbkdf2}
ALLOW_PLAINTEXT_HTTP=${ALLOW_PLAINTEXT_HTTP:-}
ISSUER_URL=${ISSUER_URL:-}
EOF

# Optional SAML signing material (PEM with real newlines inside quotes; dotenv
# accepts that). Without it the SAML endpoints answer 503, which e2e treats as
# "SAML not configured" rather than a failure.
if [ -n "$SAML_SIGNING_CERT" ]; then
  echo "SAML_SIGNING_CERT=\"$SAML_SIGNING_CERT\"" >> .dev.vars
  echo "SAML_SIGNING_KEY_PKCS8=\"$SAML_SIGNING_KEY_PKCS8\"" >> .dev.vars
elif [ -f /run/secrets/saml-cert.pem ] && [ -f /run/secrets/saml-key.pem ]; then
  # Mounted files keep their real newlines; dotenv wants the PEM quoted.
  { printf 'SAML_SIGNING_CERT="'; cat /run/secrets/saml-cert.pem; printf '"\n';
    printf 'SAML_SIGNING_KEY_PKCS8="'; cat /run/secrets/saml-key.pem; printf '"\n'; } >> .dev.vars
fi

# Local D1 lives in .wrangler/state. Non-interactive apply is safe: miniflare
# never prompts and the DB starts empty.
npx wrangler d1 migrations apply DB --local

exec npx wrangler dev --port "${PORT:-8787}" --ip 0.0.0.0
