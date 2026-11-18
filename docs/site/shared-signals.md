# Shared Signals

Shared Signals lets FlareID exchange security events with other systems in real time, using the OpenID Shared Signals Framework (CAEP and RISC). When someone's session is revoked or their account is disabled here, the systems you connect find out straight away, and the other way round.

Manage it under **Integrations → Signals**.

## Send events (outbound streams)

A stream is a receiver FlareID pushes events to.

1. Get the receiver's **Endpoint URL** and the **Audience** it expects.
2. Under **Outbound streams**, enter a name, the endpoint URL and audience.
3. Tick the events to send, or none to send all of them.

| Event | Sent when |
|---|---|
| Session revoked | Someone's sessions are ended. |
| Credential change | Someone's password or second factors change. |
| Account disabled | An account is made inactive. |
| Credential change required | Someone is flagged on the risk watchlist. |

Events are signed with FlareID's [signing keys](signing-keys.md). Failed deliveries are retried every hour.

## Receive events (inbound transmitters)

A transmitter is a trusted system that sends events to FlareID at `https://<your hostname>/ssf/receive`.

1. Under **Inbound transmitters**, enter a name, the transmitter's **Issuer** and its **JWKS URL**.
2. Give the transmitter FlareID's receive URL.

What FlareID does with an event about one of its users:

- **Session revoked**: ends all their sessions and tokens.
- **Account disabled** or **credential change required**: adds them to the [risk watchlist](cloudflare-one.md#risk-watchlist) for 24 hours.

Events that aren't signed by a key from the transmitter's JWKS URL are refused.

## Discovery

Receivers that support discovery can read FlareID's settings from `/.well-known/ssf-configuration`.
