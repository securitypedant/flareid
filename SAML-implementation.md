# SAML 2.0 in FlareID: findings and implementation plan

FlareID speaks OIDC today and the README has, until now, said SAML was
impractical on Workers. That reasoning is out of date. This document records
what changed, what "a fully compliant SAML IdP" actually means, which parts are
genuinely hard, and the staged plan for building it.

Nothing here is implemented yet. This is the design, written before the code so
that the hard decisions are made in the open rather than discovered halfway
through a signing routine.

## Contents

1. [Why this document exists](#1-why-this-document-exists)
2. [What "fully compliant" means - three different bars](#2-what-fully-compliant-means---three-different-bars)
3. [The XML problem is three problems](#3-the-xml-problem-is-three-problems)
4. [The one real exception: Cloudflare Access Signed AuthN](#4-the-one-real-exception-cloudflare-access-signed-authn)
5. [Why "canonical by construction" works](#5-why-canonical-by-construction-works)
6. [Crypto inventory: what Workers can and cannot do](#6-crypto-inventory-what-workers-can-and-cannot-do)
7. [saml2int gap analysis](#7-saml2int-gap-analysis)
8. [Library or hand-rolled](#8-library-or-hand-rolled)
9. [Design: endpoints, data model, flows](#9-design-endpoints-data-model-flows)
10. [Validation strategy](#10-validation-strategy)
11. [Staging and effort](#11-staging-and-effort)
12. [Why SAML comes last](#12-why-saml-comes-last)

---

## 1. Why this document exists

The architecture note in FlareID's README said:

> SAML needs XML canonicalization and XML-DSig signing, which is painful and
> fragile outside a Node/browser DOM environment.

Two things have changed since that was written.

**`node:crypto` is now fully implemented in Workers.** Cloudflare shipped
sign/verify in `workerd` in February 2025 and announced full `node:crypto`
support in the April 2025 changelog. The documented gaps are DSA/DH keypair
generation, `argon2`, `randomUUIDv7`, the ed448/x448 curves, and manual FIPS
toggling - none of which matter here. X.509 certificate *handling* (parsing,
PEM/DER, `X509Certificate`) is included.

**`xml-crypto`'s dependency tree is smaller than its reputation.** As of v6 its
only runtime dependencies are `@xmldom/is-dom-node`, `@xmldom/xmldom` and
`xpath` - all pure JavaScript - plus `node:crypto` internally. The upstream
"web-crypto support" issue (node-saml/xml-crypto#477) is still open, with an
AI-generated PR (#513) milestoned to v7.0 with no date attached, which is where
the "doesn't run in Workers" claim comes from. But that issue was opened in
September 2024, *before* the `node:crypto` work landed, and nobody appears to
have retested since.

So the honest position is: the blocker may simply be gone, and nobody has
checked. Section 8 says what to do about that.

More importantly, the README's framing treats XML-DSig as one monolithic
problem. It is three problems with wildly different difficulty, and the
difficult one is avoidable. That is section 3, and it is the central finding of
this document.

---

## 2. What "fully compliant" means - three different bars

This matters more than any technical detail, because one of the three bars is
both unreachable and irrelevant, and conflating them is how a project ends up
building artifact resolution nobody will ever use.

### Bar 1: OASIS conformance, "IdP" operational mode

The 2005 normative document (`saml-conformance-2.0-os`) defines operational
modes - IdP, IdP Lite, SP, SP Lite, ECP - and a matrix of what each must
implement. Full "IdP" mode requires Web Browser SSO over the HTTP-Redirect,
HTTP-POST **and HTTP-Artifact** bindings, the Single Logout profile over both
front-channel and back-channel (SOAP) bindings, the Name Identifier Management
profile, the Assertion Query/Request profile, Artifact Resolution over SOAP,
and ECP/PAOS. "IdP Lite" relaxes this mainly by dropping managed/persistent
name identifiers and some of the rarer bindings.

**Verdict: do not chase this.** There has been no active SAML 2.0 certification
programme for well over a decade - there is no body that can certify FlareID
against this matrix, and in practice no customer asks. Artifact binding and the
SOAP back-channel are effectively dead in the wild; the handful of deployments
that still use them are not going to adopt a new IdP. Building them would be
weeks of work validated by nothing.

### Bar 2: saml2int

The Kantara Initiative's *SAML V2.0 Deployment Profile for Federation
Interoperability* version 2.0 (2019). Thirty-two numbered IdP requirements plus
common requirements covering metadata and cryptographic algorithms. This is what
InCommon, eduGAIN, the UK Access Management Federation and every other serious
federation actually hold an IdP to, and it was written by people who have
operated SAML at scale for fifteen years.

**Verdict: this is the real target, and it is achievable on Workers.** Section 7
is a requirement-by-requirement gap analysis.

### Bar 3: "works with the service providers you will actually meet"

Cloudflare Access, Okta, Entra, Google Workspace, Salesforce, AWS, Zoom,
Atlassian. In practice this is a strict subset of bar 2 - most of these do not
require Single Logout at all, and until recently few required encrypted
assertions.

**Verdict: comfortably achievable. This is v1.**

### The rule for how we describe it

Never claim bare "SAML 2.0 support" in a README. State the profile:

> SAML 2.0 Web Browser SSO, service-provider-initiated, HTTP-Redirect for
> requests and HTTP-POST for responses, conformant with saml2int section 4.1.
> Not implemented: HTTP-Artifact binding, SOAP back-channel, ECP/PAOS, Name
> Identifier Management, Assertion Query/Request.

An IdP that overstates its conformance is worse than one that understates it,
because the failure shows up as somebody else's broken login.

---

## 3. The XML problem is three problems

This is the finding that makes the rest of the plan viable.

**Problem 1: generating a signature over XML we wrote ourselves.** Tractable.
Does not require a canonicalization implementation at all - see section 5.

**Problem 2: verifying a detached signature on an HTTP-Redirect binding
message.** Trivial, and involves no XML. The redirect binding signs the raw,
ordered, URL-encoded query string (`SAMLRequest=...&RelayState=...&SigAlg=...`),
not the document. Verification is one `crypto.subtle.verify` call over a byte
string we already have.

**Problem 3: verifying an XML-DSig embedded in XML somebody else produced.**
This is the hard one, and the dangerous one. It needs a real exclusive-C14N
implementation that is correct over arbitrary input, plus a parser hardened
against entity expansion and namespace trickery, plus the full XML Signature
Wrapping (XSW) defence checklist. XSW is the vulnerability class that has
produced CVEs in essentially every SAML implementation ever written -
ruby-saml, python3-saml, samlify, node-saml, Shibboleth, and more. It is not a
problem you solve by being careful; it is a problem you solve by not having it,
or by implementing a long list of specific structural checks.

### saml2int's mandatory paths never require problem 3

This is the part worth stating slowly, because it determines the whole risk
profile of the project:

- **`[SDP-IDP02]`** - IdPs MUST support the **HTTP-Redirect** binding for
  receipt of `<samlp:AuthnRequest>` messages. A signature on a redirect-binding
  request is problem 2.
- **`[SDP-IDP25]`** and **`[SDP-IDP26]`** - IdPs MUST support the
  **HTTP-Redirect** binding for receipt of `<samlp:LogoutRequest>` messages,
  and those requests MUST be signed *"via a signature created in accordance
  with the HTTP-Redirect binding"*. Again problem 2, and note the profile
  explicitly chose the easy signature form here.
- **`[SDP-MD02]`** - consumption of metadata MUST be contingent on verification
  of a signature **or a TLS server certificate**. The XML signature is STRONGLY
  RECOMMENDED, not MUST, so a deployment that fetches metadata over verified
  HTTPS is conformant.

So the entire XSW attack class can be **designed out** rather than defended
against. An IdP that only ever *generates* XML signatures and only ever
*verifies* query-string signatures has no XSW surface. That is a structural
property, not a matter of care, and it is the strongest argument that a
high-conformance SAML IdP is a reasonable thing to build on Workers.

There is exactly one exception, and it is one we will meet immediately.

---

## 4. The one real exception: Cloudflare Access Signed AuthN

Cloudflare Access is the first service provider FlareID will federate with, and
it has a feature that lands squarely in problem 3.

Access's *Signed AuthN requests* does **not** use the redirect-binding
query-string signature. Cloudflare's documentation is explicit:

> When enabled, Access sends a signature embedded in an HTTP POST request that
> contains the AuthN details.

An embedded signature in a POSTed `AuthnRequest` is an XML-DSig over foreign
XML. Supporting it means implementing problem 3.

### What v1 does about it

**v1 does not support Signed AuthN.** FlareID will reject POST-binding
`AuthnRequest` messages outright and document that `sign_request` must be left
at its default of `false` in the Access identity provider configuration. This
costs nothing for the demo suite and nothing for the overwhelming majority of
real deployments, because signed authentication requests are rarely required -
the SP is not the party making a security claim in this exchange.

### What it would take to support it later

If it is ever wanted, the implementation must follow the full XSW hardening
checklist. Listing it here so that it is not reinvented badly under time
pressure:

- Require **exactly one** `<ds:Signature>` element in the document. More than
  one is an attack, not a configuration.
- Resolve the `<ds:Reference>` URI **by ID only**, never by XPath, and require
  it to resolve to the document element itself.
- Reject any document containing more than one element with the referenced
  `ID` value.
- Reject any element of a type that carries security meaning (`Assertion`,
  `AuthnRequest`) that sits **outside** the signed subtree.
- Allow **only** the `enveloped-signature` and `exc-c14n` transforms, and
  reject a reference carrying any other transform - including a second,
  unexpected one.
- Verify against a **pinned trust store**, never against a certificate embedded
  in the message's own `KeyInfo`.
- Enforce an algorithm allowlist and reject SHA-1 signatures.
- Operate on the parsed-then-recanonicalized bytes, never on the raw input, and
  extract claims **from the verified subtree only** - never re-parse the
  original document to read attributes after verification.

The last point is the one that catches people: libraries that verify a
signature correctly and then read the user identity from a *different* parse of
the document are the textbook XSW failure.

### A second consequence: Access's certificate rotates

Access publishes its SP signing certificate at
`https://<team>.cloudflareaccess.com/cdn-cgi/access/public-cert`, and
Cloudflare's docs state it *"routinely rotates the public key as a security
measure."* So supporting Signed AuthN would need a cron-refreshed trust store
rather than a pasted PEM, and the verifier must accept any of several currently
valid certificates. That is the same machinery `[SDP-IDP32]` requires anyway
(see section 7), which is an argument for building the metadata-driven path
before the Signed AuthN path, not after.

### The useful flip side

Access also publishes **SP metadata** at
`https://<team>.cloudflareaccess.com/cdn-cgi/access/saml-metadata`, with a
per-identity-provider variant at
`/cdn-cgi/access/<identity-provider-id>/saml-metadata`. That means the
metadata-consumption path (section 7, v2) is testable against a real service
provider from day one, rather than against a fixture.

---

## 5. Why "canonical by construction" works

The reason a signing implementation does not need a canonicalization
implementation is a property of exclusive C14N (`xml-exc-c14n#`) specifically,
and it is why SAML mandates that algorithm rather than inclusive C14N.

Exclusive C14N re-renders a subtree's *visibly utilised* namespace declarations
at the subtree's apex, rather than inheriting them from ancestors. So an
`<saml:Assertion>` that declares `xmlns:saml` on itself canonicalizes to
exactly the same bytes whether it is standing alone or nested inside a
`<samlp:Response>` that also declares `saml`. Subtree extraction is stable,
which is the whole point of the algorithm.

That gives us this procedure:

1. Build the Assertion as a canonical string, with **no** `<ds:Signature>` in
   it. Declare `xmlns:saml` (and any other prefix it uses) on the
   `<saml:Assertion>` element itself.
2. SHA-256 that string. That is the `<ds:DigestValue>`. This is correct because
   the `enveloped-signature` transform means the verifier digests the Assertion
   *minus* its Signature element - which is precisely the string from step 1.
3. Build `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` with
   the prefix declared on `SignedInfo` itself, for the same apex-rendering
   reason, and sign its canonical bytes with RSASSA-PKCS1-v1_5 / SHA-256.
4. Splice the assembled `<ds:Signature>` into the Assertion immediately after
   `</saml:Issuer>` - the position the SAML schema requires.
5. Repeat the whole procedure for the `<samlp:Response>` wrapper, which
   `[SDP-IDP09]` requires to be directly signed as well.

When the service provider verifies, it parses our bytes, strips the Signature,
canonicalizes, and must arrive back at the string from step 1. That only holds
if our serializer emits genuinely canonical form.

### The traps

Every one of these is silently wrong if guessed, and "silently" is the
operative word - a lax SP will accept malformed output and a strict one will
not, so the bug ships.

**C14N escaping is not ordinary XML escaping, and the two differ in both
directions.**

| Context | Escape | Do **not** escape |
|---|---|---|
| Text nodes | `&` `<` `>` and `#xD` | `"` |
| Attribute values | `&` `<` `"` `#x9` `#xA` `#xD` | `>` |

**Structure:**

- Empty elements render as a start/end tag pair - `<a></a>`, never `<a/>`.
- Attribute order is defined, not arbitrary: namespace declarations come first
  (the default `xmlns` before any prefixed one, then sorted by prefix),
  followed by ordinary attributes sorted by namespace URI and then local name.
- No XML declaration, no DTD, no comments, no processing instructions.
- Whitespace between elements **is** a text node and **is** part of the digest.
  Emit none - no pretty-printing, no indentation, no trailing newline inside a
  signed subtree.
- Never emit CRLF. A `#xD` must be escaped, so a stray carriage return silently
  changes the digest.

**SAML-specific:**

- `ID` attributes are `xsd:ID`, which must not begin with a digit. Prefix
  generated identifiers with `_`.
- `IssueInstant` is `xsd:dateTime` in UTC. Some older service providers reject
  fractional seconds, so emit `YYYY-MM-DDTHH:MM:SSZ`. Note that the existing
  codebase reaches for `toISOString()` everywhere, which emits `.000Z` - a
  SAML-specific formatter is needed rather than reuse.

None of this is conceptually difficult. All of it has to be verified by an
independent implementation rather than by reading, which is why section 10
exists.

---

## 6. Crypto inventory: what Workers can and cannot do

Checked against the Workers Web Crypto supported-algorithms table and the
`node:crypto` documentation.

### Everything saml2int requires is available

saml2int `[SDP-ALG01]` mandates a specific algorithm set. All of it is present:

| Requirement | Algorithm URI | Workers |
|---|---|---|
| Digest | `xmlenc#sha256` | `SHA-256` via `crypto.subtle.digest` |
| Signature | `xmldsig-more#rsa-sha256` | `RSASSA-PKCS1-v1_5` + SHA-256 |
| Signature (alternative) | `xmldsig-more#ecdsa-sha256` | `ECDSA` P-256 + SHA-256 |
| Block encryption | `xmlenc11#aes128-gcm` / `aes256-gcm` | `AES-GCM` |
| Key transport | `xmlenc#rsa-oaep-mgf1p` | `RSA-OAEP` |
| Key transport digest | `xmldsig#sha1` | `SHA-1` is a supported digest |

One item to confirm in the spike: the mandated key transport is
`rsa-oaep-mgf1p`, whose digest is **SHA-1** and whose mask generation function
is MGF1-with-SHA-1. Workers lists both RSA-OAEP and SHA-1, so
`{ name: "RSA-OAEP", hash: "SHA-1" }` should import and encrypt - but
BoringSSL-plus-FIPS constraints have produced surprises in `node:crypto`
before, so prove it rather than assume it. If Web Crypto refuses, `node:crypto`'s
`publicEncrypt` with `RSA_PKCS1_OAEP_PADDING` and `oaepHash: "sha1"` is the
fallback.

Also available and needed:

- `DecompressionStream("deflate-raw")` for redirect-binding payloads, which are
  raw-deflated then base64-encoded. Built in, no dependency.
- `CompressionStream("deflate-raw")` for outbound `LogoutRequest` messages.
- Extracting a service provider's RSA public key from the X.509 certificate in
  its metadata: `node:crypto`'s `X509Certificate` parses the PEM, and
  `cert.publicKey.export({ type: "spki", format: "der" })` yields exactly what
  `crypto.subtle.importKey("spki", ...)` wants. This avoids hand-rolling an
  ASN.1 walk to find the SubjectPublicKeyInfo.

### The one thing Workers cannot do

**Minting an X.509 certificate.** Workers cannot, and neither can `node:crypto`
in any runtime - Node has never had certificate generation. But SAML requires
one: service providers want a signing certificate rather than a bare public
key, and Cloudflare's own prerequisites state *"the IdP must include the
signing public key in the SAML response"*, meaning the certificate has to be
embedded in each signature's `KeyInfo`.

So certificate generation is an **offline build step**, not a runtime concern:
`scripts/generate-saml-cert.mjs` mints a self-signed certificate using
`node-forge` as a devDependency - or `openssl` when it is on the path - exactly
as `scripts/generate-keypair.mjs` already does for the OIDC signing key. The
certificate PEM becomes a public `var` (it is published in metadata, so it is
not a secret) and the private key a `wrangler secret`.

Certificate **expiry** then becomes an operational problem that the software has
to surface, because Cloudflare's docs carry an explicit warning about it: after
the signing certificate expires, SSO breaks and the certificate must be
regenerated and re-uploaded. So `/admin` must show the expiry date and warn
ahead of it, and the metadata endpoint must reflect it.

---

## 7. saml2int gap analysis

Requirement by requirement, grouped by how much work each represents.

### Already satisfied by the existing architecture

- `[SDP-IDP03]` - request-receipt endpoints protected by TLS. Workers only
  serves HTTPS.
- `[SDP-IDP21]` - a session concept that can be terminated. `sessions` in D1
  already supports listing and revocation.
- Attribute data to assert - users already carry display name, given/family
  name, job title, department, manager, employee number and flat group
  membership.

### Straightforward - v1

- **`[SDP-IDP02]`** HTTP-Redirect receipt of `AuthnRequest`.
  `DecompressionStream("deflate-raw")` is built in.
- **`[SDP-IDP04]`/`[SDP-IDP05]`** Accept unsigned requests generally; reject
  unsigned when the SP's metadata carries `AuthnRequestsSigned="true"`; verify
  the signature when one is present, and fail the request if verification
  fails. All redirect-binding, so all problem 2.
- **`[SDP-IDP06]`** Verify `AssertionConsumerServiceURL` against the SP's
  registered endpoints, falling back to the metadata default when the request
  omits it. Implemented as an exact-match allowlist - this is the control that
  stops an unsigned request redirecting a signed assertion somewhere
  unregistered, so it is load-bearing in v1 given that unsigned requests are
  accepted.
- **`[SDP-IDP07]`** Honour `ForceAuthn` with a real re-authentication
  challenge, and reflect it in `AuthnInstant`. Access exposes `force_authn`, so
  this gets exercised immediately rather than theoretically.
- **`[SDP-IDP08]`/`[SDP-IDP09]`/`[SDP-IDP10]`** POST-binding Response, directly
  signed at the `<samlp:Response>` level, containing exactly one assertion with
  exactly one `<saml:AuthnStatement>` and zero or one
  `<saml:AttributeStatement>`. We sign both Response and Assertion, since
  `[SDP-IDP10]` permits the assertion signature and some SPs expect it.
- **`[SDP-IDP12]`** A transient-format `<saml:NameID>` in every assertion, for
  logout purposes.
- **`[SDP-IDP18]`/`[SDP-IDP19]`/`[SDP-IDP20]`** Attributes carrying
  `NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"`, each value a
  single text node, and multi-valued attributes expressed as repeated
  `<saml:AttributeValue>` elements rather than a delimited string. Worth
  flagging: this is **not** the shape of the OIDC `groups` claim, which is a
  JSON array in one claim. The attribute mapper is deliberate new work, not a
  reuse of `buildClaims()`.

### Moderate - v1.5

- **`[SDP-IDP11]` Encrypted assertions are mandatory over the POST binding.**
  This surprised me and is worth calling out: saml2int does not treat
  encryption as optional hardening. Since `[SDP-IDP08]` mandates POST for
  responses, encryption is effectively always required for conformance. The
  mechanics are fine - AES-128/256-GCM content encryption with RSA-OAEP key
  transport, all present in Web Crypto, and all *generation*, so section 5's
  canonical-by-construction argument applies to the `<xenc:EncryptedData>`
  structure too. Access gained assertion encryption in June 2026, generates its
  own certificate and publishes it as PEM or via its SAML metadata endpoint, so
  there is a real counterparty to test against.
- **`[SDP-IDP21]`, `[SDP-IDP24]`-`[SDP-IDP31]` Single Logout, receipt only.**
  The mandatory half is: accept a signed redirect-binding `<samlp:LogoutRequest>`,
  terminate the IdP session, and return a signed `<samlp:LogoutResponse>` whose
  `<samlp:StatusCode>` honestly reflects whether termination succeeded.
  **Propagation to other service providers is only `MAY` (`[SDP-IDP23]`)**,
  which is the merciful part - fanning logout out to every SP the user has a
  session with, over hidden iframes, is the flaky and expensive half and it is
  optional. `[SDP-IDP22]` even permits offering the user the choice to keep
  their IdP session.
- **Service provider metadata import.** Parsing foreign XML is fine -
  `@xmldom/xmldom` is pure JS and runs in Workers. It is only *verifying
  signatures over* foreign XML that is dangerous, and `[SDP-MD02]` permits
  resting trust on TLS. So: fetch over HTTPS, parse, extract entity ID, ACS
  endpoints, NameID formats, `AuthnRequestsSigned`, signing certificates and
  the encryption certificate.

### Architectural - v2

- **`[SDP-MD01]`** is the significant one: deployments MUST provision their
  behaviour *"based solely on the consumption of SAML Metadata on an automated,
  periodic or real-time basis."* Service provider configuration has to come
  from metadata URLs on a refresh schedule, not from fields an administrator
  typed. That is a different design from FlareID's current per-client admin
  form, and it is an architectural change rather than a feature. A Cron Trigger
  plus a D1 registry plus a KV cache suits Workers well.
- **`[SDP-MD03]`** Reject metadata with no `validUntil` on its root element, or
  whose `validUntil` extends beyond a configured threshold.
- **`[SDP-IDP32]`** Accept multiple signing certificates per service provider
  and validate against any of them, so key rollover does not require downtime.
  This is also exactly what Access's rotating public certificate needs.
- **`[SDP-IDP13]`/`[SDP-IDP14]`/`[SDP-IDP15]`** Non-transient subject
  identification via the `subject-id` and/or `pairwise-id` attributes, with our
  supported scopes enumerated in metadata using `<shibmd:Scope>` (non-regexp),
  and honouring the metadata-based mechanism by which an SP signals which it
  requires. `pairwise-id` is a per-SP pseudonymous identifier - the standard
  construction is an HMAC over the user identifier and the SP's entity ID,
  which is cheap, but it has to be done deliberately.
- **`[SDP-MD05]`-`[SDP-MD12]`** Our own published metadata: public keys as
  X.509 certificates in `<md:KeyDescriptor>`, RSA at least 2048 bits (3072
  recommended for new deployments), an `<mdui:UIInfo>` carrying at least
  `<mdui:DisplayName>` and `<mdui:Logo>` (https URL or a `data:` URI), an
  `<md:ContactPerson contactType="technical">` with an `<md:EmailAddress>`, and
  an `errorURL` on `<md:IDPSSODescriptor>` resolving to an HTML page.

### Never implementing, and saying so

Artifact binding and Artifact Resolution, the SOAP back-channel, ECP/PAOS, Name
Identifier Management, Assertion Query/Request. These are precisely what
separates OASIS "IdP" operational mode from saml2int, and nobody deploys them.
The README should name them as out of scope rather than leaving a reader to
discover the gap.

---

## 8. Library or hand-rolled

As section 1 notes, `xml-crypto` may now work unmodified in Workers under
`nodejs_compat`, and nobody has checked. One caveat if testing it: older
versions of wrangler bundled an `unenv` polyfill that shadowed the built-in
`node:crypto` and threw "not implemented" even where the runtime supported the
call, so pin a recent wrangler and a recent `compatibility_date` before
concluding anything.

**The recommendation is to hand-roll generation, and to treat `xml-crypto` as a
testing oracle rather than a dependency.** The reasoning:

- Generation is roughly 400 dependency-free lines given section 5's procedure.
  The library's value would be canonicalization, and canonicalization is
  exactly what we do not need for generation.
- `xpath` evaluation and DOM construction run on every single login. That is
  CPU time and bundle size on the hot path, for a document we already know the
  shape of because we built it.
- The library's real value is the *verification* path - problem 3 - which
  sections 3 and 4 deliberately design out of v1.
- A dependency that parses attacker-controlled XML is a dependency whose CVEs
  become our CVEs. Not taking it is a security decision as much as a
  performance one.

Run the spike regardless. If `xml-crypto` works under `nodejs_compat`, it is a
free second implementation to differential-test our own output against in CI
(section 10), which is worth more than it would be as a runtime dependency.

---

## 9. Design: endpoints, data model, flows

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/saml/metadata` | IdP metadata: entity ID, SSO endpoints, signing certificate(s), NameID formats, `mdui:UIInfo`, contact, `errorURL` |
| `GET` | `/saml/sso` | HTTP-Redirect binding - the normal SP-initiated entry point |
| `POST` | `/saml/sso` | HTTP-POST binding. **Rejected in v1** (see section 4) |
| `GET` | `/saml/slo` | HTTP-Redirect `LogoutRequest` / `LogoutResponse` receipt (v1.5) |
| `GET` | `/admin/saml` | Service provider registry UI |

### Data model

A `saml_service_providers` table, carrying:

- `entity_id` (unique), display name
- `acs_urls` - JSON array, exact-match allowlist
- `default_acs_url` - for requests that omit `AssertionConsumerServiceURL`
- `nameid_format`, `attribute_map` (JSON)
- `sign_assertion`, `sign_response` flags
- `want_authn_requests_signed`
- `signing_certs` - JSON array, **plural**, for `[SDP-IDP32]` rollover
- `encryption_cert`, `encrypt_assertions`
- `metadata_url`, `metadata_last_refreshed_at`, `metadata_valid_until`

### Flow reuse

The existing login machinery slots in with almost no change, which is the nicest
part of the design. `src/lib/authorize-state.ts` already stores a pending
login flow in KV behind a `kind` discriminator - currently only `"oidc"` - and
`src/routes/login.ts` resumes whatever that flow says when authentication
completes. A `"saml"` variant sits beside it, and MFA, forced MFA enrolment,
trusted devices, rate limiting, audit logging and existing-session SSO all come
for free. The only new work at the end of the flow is building and posting the
Response instead of redirecting with a code.

`SessionIndex` in the `AuthnStatement` is set to the FlareID `sessions` row id,
which is the groundwork Single Logout needs later.

### Security checks on every request

- `InResponseTo` bound to a stored, single-use request record
- `Audience` restriction naming the SP's entity ID
- `Destination` matching our own SSO URL
- Assertion ID replay cache in KV, TTL'd past `NotOnOrAfter`
- `NotBefore` / `NotOnOrAfter` window of about five minutes, with a small clock
  skew allowance
- Exact ACS URL match against the allowlist
- Algorithm allowlist; SHA-1 signatures refused

---

## 10. Validation strategy

This section is what makes any conformance claim credible. SAML's failure mode
is silent - a malformed signature that a lax SP accepts and a strict one
rejects - so "we read it carefully" is not a validation strategy.

- **Golden-file tests.** Fixed inputs produce byte-exact expected canonical XML,
  checked into the repo. A serialization regression then fails loudly instead
  of producing output that merely looks right.
- **`xmlsec1 --verify` in CI.** An independent implementation verifying our
  generated Responses and Assertions. This is the single highest-value test:
  our own code agreeing with itself proves nothing.
- **Differential testing against `xml-crypto`** in Node over the same inputs,
  if the spike shows it usable.
- **Live service providers.** Cloudflare Access as the primary target, plus
  SimpleSAMLphp and a Shibboleth SP in containers - Shibboleth because it is
  the strictest widely deployed implementation and will reject things Access
  tolerates. A public test SP such as `sptest.iamshowcase.com` for a quick
  smoke check.
- **Negative and security tests.** XSW vectors from *On Breaking SAML* and the
  SAML Raider corpus; replayed assertion IDs; expired `NotOnOrAfter`; wrong
  `Audience`; wrong `Destination`; mismatched or absent `InResponseTo`; an
  `AuthnRequest` naming an unregistered ACS URL; a signature made with a
  different key; an unsigned request from an SP whose metadata demands signed
  requests.

---

## 11. Staging and effort

| Stage | Contents | Effort |
|---|---|---|
| **Spike** | Prove canonical-by-construction signing against `xmlsec1` and against Access. Confirm RSA-OAEP with SHA-1. Test whether `xml-crypto` runs under `nodejs_compat`. | ~0.5 day |
| **v1** - Access-compatible | SP registry in `/admin`; `GET /saml/sso` redirect binding; signed Response and Assertion; auto-submitting POST form to the ACS; `GET /saml/metadata`; transient NameID; attribute mapping; `RelayState` passthrough; replay / `Audience` / `Destination` / `InResponseTo` checks; `ForceAuthn`. | 2-3 sessions |
| **v1.5** | Encrypted assertions; Single Logout receipt with signed `LogoutResponse`; SP metadata import. | 2 sessions |
| **v2** - saml2int | Metadata-driven SP registry with Cron refresh; `subject-id` / `pairwise-id` with `shibmd:Scope`; multiple SP signing certificates; the full metadata requirements. | 2-3 sessions |

---

## 12. Why SAML comes last

SAML is achievable here, to a genuinely high conformance bar. It should still
not be the next thing built.

Adding it roughly doubles the IdP's protocol attack surface and introduces a
cryptographic format whose mistakes do not announce themselves. At the time of
writing FlareID has no automated tests at all, no CSRF defence on its
administrative forms, no security headers, and password hashing at a third of
current guidance. Building the harder protocol on top of a codebase that cannot
demonstrate the easier one is correct is the wrong order of work.

The test harness that the open-sourcing effort introduces is also precisely the
thing that makes SAML safe to write - golden files, an independent verifier in
CI, and negative tests are not optional extras here, they are the only reason to
believe the output is right. Build that first, close the P0 items in
`ROADMAP.md`, and then come back to this document.
