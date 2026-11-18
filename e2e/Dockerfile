# A self-contained FlareID instance for end-to-end testing.
#
#   docker build -f e2e/Dockerfile -t flareid-e2e .
#   docker run --rm -p 8787:8787 flareid-e2e
#
# The container runs `wrangler dev` (miniflare) with a local D1 that has every
# migration applied, a local KV namespace, and throwaway secrets generated at
# start. Bootstrap token defaults to "e2e-bootstrap-token" (override with
# -e BOOTSTRAP_TOKEN=...).
#
# Drive it with `node e2e/smoke.mjs`, or for persistence across restarts mount
# a volume on /app/.wrangler.

FROM node:22-bookworm-slim

# workerd's outbound-TLS service needs a system CA bundle; slim images lack it.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

EXPOSE 8787
ENTRYPOINT ["sh", "e2e/entrypoint.sh"]
