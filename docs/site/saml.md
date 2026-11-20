# SAML apps

SAML apps (service providers) are applications that sign people in with FlareID over SAML 2.0, such as SaaS apps or Cloudflare Access. Manage them under **Integrations → SAML apps**.

## Before you start

SAML needs a signing certificate. Run `npm run saml:keygen` and set the two secrets it prints, `SAML_SIGNING_KEY_PKCS8` and `SAML_SIGNING_CERT`, on the Worker. Until then the SAML pages show a warning and `/saml/*` doesn't answer.

## Add a SAML app

The quickest way is from the app's metadata:

1. Go to **Integrations → SAML apps → + New service provider**.
2. Under **Import from SP metadata**, enter the app's **Metadata URL**, or paste its metadata XML.
3. Select **Import metadata**. The entity ID, ACS URLs, certificates, logout URL and NameID format are filled in. A metadata URL is re-read daily, so certificate changes are picked up.

Or enter the details by hand:

| Field | What to enter |
|---|---|
| **Entity ID (Issuer)** | The app's entity ID, from its SAML settings. |
| **Assertion Consumer Service URLs** | Where FlareID posts the sign-in response. |
| **NameID format** | How the person is identified: email address, persistent or transient — or **none** to omit the NameID from the assertion entirely. |
| **Attribute map** | Which attributes the app receives. Leave empty for email, name and groups. |
| **SP signing certificates** | Only if the app signs its requests. |
| **Single Logout URL** | Only if the app supports single logout. |
| **SP encryption certificate** | Only if the app wants encrypted assertions. |

## Configure the app

On the SAML app's page, FlareID shows what to enter on the app's side:

| App field | Value |
|---|---|
| Entity ID / Issuer | `https://<your hostname>` |
| SSO URL | `https://<your hostname>/saml/sso` |
| Metadata URL | `https://<your hostname>/saml/metadata` |
| Signing certificate | Download it from the page, or from `/saml/cert.pem` |

If the app accepts a metadata URL, use that.

## Attribute map

The attribute map is JSON that names each attribute the app receives and where its value comes from. For example:

```json
{ "email": "email", "firstName": "given_name", "lastName": "family_name", "memberOf": "groups" }
```

Values can be `email`, `upn`, `username`, `name`, `given_name`, `family_name`, `groups`, the HR fields such as `job_title` and `department`, or your own [schema](schemas.md) attributes.

For full control over what goes on the wire, **Attribute definitions** (JSON, on the same form) lets each released attribute carry an arbitrary SAML `Name` and an optional `NameFormat`:

```json
[
  { "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "field": "email" },
  { "name": "memberOf", "field": "groups", "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" }
]
```

When definitions are present they replace the map entirely; the field values use the same vocabulary.

## Restrict who can use the app

**Restrict to groups** limits the app to members of the chosen groups; empty means everyone. Restricted apps are hidden from other people's My account launchpad, and a sign-in from someone outside the groups is answered with a SAML `RequestDenied` status instead of an assertion.

## Instance settings

On **Applications → SAML → Settings**, **Disabled algorithms** lists signature/encryption algorithms this instance refuses — by URI, fragment or short name (`sha1`, `rsa-1_5`). Choosing a denied algorithm anywhere is rejected, and an SP whose policy resolves to one fails closed rather than emitting it.

## Good to know

- Sign-in starts from the app (SP-initiated). FlareID signs both the response and the assertion.
- Signed requests must use the HTTP-Redirect binding. Requests that embed an XML signature are refused, so leave **Signed AuthN requests** off in Cloudflare Access.
- The signing certificate's expiry date is shown on each app's page. Plan a rollover before it expires.
