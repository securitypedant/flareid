# LDAP in FlareID: design and implementation plan

FlareID speaks OIDC and SAML. This document specifies an **LDAP interface**: a
read-only LDAPv3 server, running inside the FlareID Worker, that lets legacy
applications and devices authenticate FlareID users and look up their groups.

Nothing here is implemented yet. Like SAML-implementation.md, this is the
design written before the code, so the decisions are made in the open. Where a
decision is marked **Decision**, implement it as written unless you find a
concrete reason it cannot work - and if you do, record the reason here.

## Contents

1. [Scope in one paragraph](#1-scope-in-one-paragraph)
2. [Why this shape - the evidence](#2-why-this-shape---the-evidence)
3. [Platform: how TCP reaches a Worker](#3-platform-how-tcp-reaches-a-worker)
4. [Architecture and module layout](#4-architecture-and-module-layout)
5. [Wire protocol: what to implement](#5-wire-protocol-what-to-implement)
6. [The directory tree (DIT)](#6-the-directory-tree-dit)
7. [LDAP apps: the data model](#7-ldap-apps-the-data-model)
8. [Entries and attributes](#8-entries-and-attributes)
9. [Bind](#9-bind)
10. [Search, Compare and filters](#10-search-compare-and-filters)
11. [Active Directory compatibility](#11-active-directory-compatibility)
12. [POSIX (Linux / SSSD) support](#12-posix-linux--sssd-support)
13. [MFA over LDAP](#13-mfa-over-ldap)
14. [Security requirements](#14-security-requirements)
15. [Admin UI, provisioning API, audit](#15-admin-ui-provisioning-api-audit)
16. [Deployment](#16-deployment)
17. [Testing](#17-testing)
18. [Phasing](#18-phasing)
19. [Explicitly out of scope](#19-explicitly-out-of-scope)
20. [Open questions to verify on the platform](#20-open-questions-to-verify-on-the-platform)
21. [Reference: wire constants](#21-reference-wire-constants)

---

## 1. Scope in one paragraph

An application connects over **LDAPS** (TLS from the first byte, ports 636 and
3269), binds with a per-application service account, searches for a user,
then binds as that user with the password they typed. FlareID answers from D1:
users, groups (explicit and dynamic), and memberships, presented as a
standards-conformant LDAPv3 directory with enough Active Directory and POSIX
emulation that applications configured for AD or for Linux logins work
unchanged. The interface is **read-only**, has **no StartTLS**, **no SASL**, and
**no Kerberos/NTLM**. It is an authentication facade, not a directory server.

---

## 2. Why this shape - the evidence

These findings drove the decisions below. You don't need to re-research them;
they are here so the trade-offs make sense.

**LDAPS-only is viable.** Cloud LDAP products already ship that restriction:

- Google Secure LDAP is LDAPS-only on 636, *requires* SNI and client
  certificates, and still documents working setups for Jira, Jenkins, GitLab,
  SSSD, macOS, pfSense, OpenVPN, Splunk, PaperCut, Ivanti, Puppet, Sophos
  Mobile and FreeRADIUS.
  <https://knowledge.workspace.google.com/admin/apps/connect-ldap-clients-to-the-secure-ldap-service>
- Microsoft Entra Domain Services exposes secure LDAP to the internet on 636
  only.
- Okta's LDAP Interface implements only Bind, Unbind and Search, TLS 1.2 only,
  and does MFA by having users type `password,123456` or `password,push`.
  <https://help.okta.com/en-us/content/topics/directory/ldap-interface-limitations.htm>
- JumpCloud's cloud LDAP is read-only, RFC 2307, with `memberOf`.
  <https://jumpcloud.com/support/use-cloud-ldap>

**Who it serves.** Self-hosted apps (Jira/Confluence DC, GitLab, Jenkins,
Grafana, Nextcloud, Splunk, Jamf Pro, PaperCut, Vault, Harbor, Gitea),
firewalls and VPNs (Palo Alto uses LDAPS when the port is 636; FortiGate, Cisco
ASA, pfSense/OPNsense, OpenVPN, Sophos), Linux hosts via SSSD (which accepts
`ldaps://` and refuses to authenticate over an unencrypted channel), vCenter's
OpenLDAP identity source, Proxmox, NAS web logins, and printers/MFPs.

**What it loses, by design.**
- StartTLS-only clients, notably **Meraki MX/MR AD integration** (StartTLS on
  3268) and Odoo core. Recovering them needs TLS terminated inside the Worker;
  that is phase 3, not this design.
- Very old devices that only speak TLS 1.0 / SSL 3 (Spectrum's minimum is TLS
  1.1).
- Anything that needs AD *as a domain*: domain join, Kerberos, NTLM, SMB file
  share authentication (needs NT hashes, which FlareID's scrypt/PBKDF2 hashes
  cannot provide), Group Policy.

**The biggest multiplier is AD emulation, not StartTLS.** Most real
deployments of these apps are configured in "Active Directory mode": they bind
as `DOMAIN\user` or `user@domain`, filter on `sAMAccountName`,
`objectCategory`, `userAccountControl` bit flags, and nested-group matching
rule `1.2.840.113556.1.4.1941`. Section 11 makes those work.

---

## 3. Platform: how TCP reaches a Worker

LDAP is raw TCP, which Workers historically could not accept. Two recent
platform features change that:

1. **The `connect()` handler.** A Worker can export
   `connect(socket, env, ctx)`, which receives a `Socket` (the same type that
   `connect()` from `cloudflare:sockets` returns): `socket.readable`,
   `socket.writable`, `socket.opened` (resolves to
   `SocketInfo { remoteAddress?, localAddress? }`), `socket.closed`,
   `socket.close()`. The installed `@cloudflare/workers-types`
   (5.20261027.1) already types `connect?` on `ExportedHandler`.
   <https://developers.cloudflare.com/workers/runtime-apis/handlers/connect/>
2. **Spectrum with a Worker origin** (private beta). A Spectrum application
   with `traffic_type: "worker"` and `origin_worker_id` hands each inbound TCP
   connection to that Worker's `connect()` handler. For Worker origins, `tls`
   may only be `"off"` or `"flexible"`; `proxy_protocol` and Argo are
   unavailable. Sign-up and announcement:
   <https://blog.cloudflare.com/grpc-workers/>. API field reference:
   <https://developers.cloudflare.com/api/resources/spectrum/subresources/apps/>.

**Decision: `tls: "flexible"`.** Spectrum terminates TLS at the edge with the
zone's edge certificate, and the Worker receives plaintext LDAP bytes. This is
what makes LDAPS possible without a TLS stack in the Worker. The consequence is
that the Worker never sees SNI or client certificates, and cannot do StartTLS.

**Decision: same Worker.** Add `connect` to the existing default export in
`src/index.ts` rather than deploying a second Worker. It shares D1, KV, the
password, rate-limit, TOTP, group and audit code with no RPC layer. The cost -
every FlareID deploy drops open LDAP connections - is acceptable: LDAP clients
reconnect, and SSSD caches. If this becomes a problem, move the handler to a
`WorkerEntrypoint` in a separate Worker later; the module layout in section 4
keeps that cheap.

Note: the public docs page still says connections only arrive from another
Worker over a service binding; the Spectrum path is the private beta. Section
20 lists what to verify once the beta is enabled.

---

## 4. Architecture and module layout

```
src/index.ts                export default { fetch, scheduled, connect }
                            connect: (socket, env, ctx) => handleLdapConnection(socket, env, ctx)
src/ldap/
  index.ts                  handleLdapConnection: socket <-> LdapConnection, idle timer, teardown
  connection.ts             LdapConnection: per-connection state machine (see below)
  ber.ts                    BER/DER reader + writer (hand-rolled, no dependency)
  protocol.ts               LDAPMessage decode/encode, op tags, result codes, controls
  filter.ts                 Filter AST from BER; evaluation; SQL push-down for simple cases
  dn.ts                     DN parse / normalise / escape (RFC 4514)
  directory.ts              Snapshot of users/groups/memberships, built from D1; entry materialisation
  entries.ts                User/group/rootDSE/subschema/container entry builders, attribute mapping
  bind.ts                   Bind name resolution, password + OTP checks, service-account binds
  search.ts                 Scope handling, attribute selection, size limits, paging
  ad.ts                     objectGUID/objectSid encoding, AD matching rules, AD attributes
  posix.ts                  uidNumber/gidNumber/home/shell
  apps.ts                   ldap_apps CRUD, secret hashing, slug rules
  settings.ts               ldap_* settings accessors (wraps src/lib/settings.ts)
```

**Decision: hand-roll the BER codec and protocol.** It is a few hundred lines,
and every existing JS LDAP server library (ldapjs and friends) is built on
Node's `net` module, which does not apply here. This matches FlareID's existing
stance on TOTP and canonical-by-construction SAML: no dependency in the
authentication path when the code is small and testable.

**`LdapConnection` is transport-agnostic.** It takes a `ReadableStream<Uint8Array>`
and a `WritableStream<Uint8Array>` (or exposes `onBytes(chunk)` and an output
sink). `src/ldap/index.ts` adapts the `Socket` to it. This is what lets the
whole protocol be tested in vitest with a `TransformStream` pair standing in
for the socket (section 17).

Per-connection state:

```ts
interface ConnectionState {
  id: string;                         // random, for logs
  remoteIp: string | null;            // from socket.opened.remoteAddress, if Spectrum provides it
  bound:
    | { kind: "anonymous" }
    | { kind: "service"; app: LdapAppRow }
    | { kind: "user"; userId: number; app: LdapAppRow | null };
  app: LdapAppRow | null;             // app context; sticky once established (section 9)
  pagedSearches: Map<string, PagedState>;  // cookie -> state, RFC 2696 (connection-scoped)
  snapshot: { at: number; dir: DirectorySnapshot } | null;  // short-lived cache, section 10
  failedBinds: number;                // per-connection cap, section 14
  lastActivity: number;
}
```

**Framing.** TCP chunks do not align with LDAP messages. Buffer bytes, parse
one complete top-level TLV at a time (definite lengths only), and process
messages **sequentially in arrival order** (RFC 4511 allows servers to do
this). Reject a declared message length above `LDAP_MAX_PDU` (64 KiB) with a
Notice of Disconnection and close.

---

## 5. Wire protocol: what to implement

LDAPv3, RFC 4511. Constants are in section 21.

| Operation | Support | Behaviour |
|---|---|---|
| BindRequest, simple | **Yes** | Section 9. `version` must be 3, otherwise `protocolError`. |
| BindRequest, SASL | No | `authMethodNotSupported` (7). |
| UnbindRequest | **Yes** | Close the connection; no response. |
| SearchRequest | **Yes** | Section 10. |
| CompareRequest | **Yes** | `compareTrue`/`compareFalse`/`noSuchObject`/`undefinedAttributeType`. Apache `mod_authnz_ldap` uses Compare for `Require ldap-group`. |
| AbandonRequest | **Yes** | No response. Drops paged-search state for that message ID. |
| ExtendedRequest: WhoAmI `1.3.6.1.4.1.4203.1.11.3` | **Yes** | RFC 4532. Returns `dn:<bound DN>` or empty for anonymous. |
| ExtendedRequest: StartTLS `1.3.6.1.4.1.1466.20037` | No | `protocolError` (2), diagnostic "StartTLS is not supported; use LDAPS". |
| ExtendedRequest: Password Modify `1.3.6.1.4.1.4203.1.11.1` | No | `unwillingToPerform` (53), diagnostic pointing at the FlareID account page. |
| Any other ExtendedRequest | No | `protocolError` (2). |
| Add / Modify / Delete / ModifyDN | No | `unwillingToPerform` (53), "directory is read-only". |
| Notice of Disconnection (unsolicited) | **Sent** | On idle timeout, PDU too large, too many failed binds, LDAP disabled, shutdown. |

**Controls.**

| Control | OID | Support |
|---|---|---|
| Simple Paged Results | `1.2.840.113556.1.4.319` | **Yes** (section 10). Required by SSSD, Atlassian, Grafana, AD-mode clients. |
| Server-side sort | `1.2.840.113556.1.4.473` | No. If critical: `unavailableCriticalExtension` (12). If not: ignore. |
| ManageDsaIT | `2.16.840.1.113730.3.4.2` | Accept and ignore (there are no referrals). |
| Any other control | - | If `criticality` is TRUE: `unavailableCriticalExtension` (12). Otherwise ignore. |

**Root DSE** (base search on DN `""`, any filter matching, readable
anonymously per RFC 4512):

```
namingContexts:            dc=example,dc=com
defaultNamingContext:      dc=example,dc=com        (AD clients read this)
rootDomainNamingContext:   dc=example,dc=com
subschemaSubentry:         cn=Subschema
supportedLDAPVersion:      3
supportedControl:          1.2.840.113556.1.4.319
supportedExtension:        1.3.6.1.4.1.4203.1.11.3
supportedSASLMechanisms:   (none)
supportedFeatures:         1.3.6.1.4.1.4203.1.5.1   ("*" / "+" attribute selection)
vendorName:                FlareID
vendorVersion:             <package.json version>
dnsHostName:               <ldap hostname setting>
```

**Decision: do not advertise `supportedCapabilities`
`1.2.840.113556.1.4.800` (LDAP_CAP_ACTIVE_DIRECTORY_OID).** Clients that see
it assume full AD (GSSAPI, DirSync, tokenGroups) and fail in harder-to-debug
ways. Apps choose AD behaviour from their own config, which is enough.

**Subschema entry** `cn=Subschema` (objectClass `subschema`): publish
`objectClasses`, `attributeTypes`, `ldapSyntaxes` and `matchingRules` for
exactly what section 8 exposes, using the standard definitions from RFC 4519
(core), RFC 4524 (cosine), RFC 2798 (inetOrgPerson), RFC 2307bis (POSIX),
RFC 4530 (entryUUID), the `memberOf` overlay definition, and the MS-ADSC
definitions for the AD attributes. Apache Directory Studio, vCenter and some
Java clients read it. Generate it from one table in `entries.ts` so the schema
and the entries cannot drift.

---

## 6. The directory tree (DIT)

**Base DN.** Derived from the default domain: `example.com` -> `dc=example,dc=com`.
Overridable with the `ldap_base_dn` setting. Changing it breaks every
configured client, so the admin UI must warn.

**Decision: one branch per LDAP app.** Each app sees the directory under its
own subtree:

```
dc=example,dc=com                          domain/dcObject - the naming context
├── ou=services                            organizationalUnit
│   └── cn=jira                            the jira app's service account (bind only, never returned by search)
├── ou=jira                                organizationalUnit - jira's view
│   ├── ou=people
│   │   ├── uid=alice
│   │   └── uid=bob
│   └── ou=groups
│       └── cn=Engineering
└── ou=gitlab                              gitlab's view
    ├── ou=people
    └── ou=groups
```

Why, rather than one shared `ou=people`:

1. **Attribution.** A user bind carries a DN the app got from its own search,
   e.g. `uid=alice,ou=people,ou=jira,dc=example,dc=com`. The DN itself tells
   FlareID which app is asking, so per-app policy (who may sign in, MFA mode)
   applies even when the app opens a fresh connection for the user bind, as
   Spring LDAP, Jenkins and many others do.
2. **Data minimisation.** Each app sees only the users and groups it was
   granted, which is the LDAP equivalent of ROADMAP item 15 (per-client claim
   allowlists).
3. **It costs nothing.** Clients configured with base `dc=example,dc=com` and a
   subtree search still work: the search is confined to the bound app's
   branch (section 10).

Rules:

- The app slug is the branch RDN value (`ou=<slug>`). Slugs match
  `^[a-z][a-z0-9-]{1,30}$`. `services` is reserved.
- User RDN is `uid=<username>`: `users.username` is unique and lowercase. Don't
  use `cn` (display names are not unique).
- Group RDN is `cn=<group name>`: `groups.name` is unique. Escape per RFC 4514
  (commas, `+`, `"`, `\`, `<`, `>`, `;`, leading `#`/space, trailing space).
- DN comparison is on the normalised form: attribute types lowercased,
  values compared case-insensitively after unescaping, insignificant spaces
  removed. Accept `UID=alice,OU=People,...` as the same DN.

---

## 7. LDAP apps: the data model

An **LDAP app** is a registered client, the LDAP equivalent of an OIDC client
or a SAML SP. It owns a service account (a bind DN and a secret) and a policy.
Following `api_keys`, a service account is **not a user**: "a key is not a
person".

### Migration `migrations/0013_ldap.sql`

```sql
-- LDAP interface: registered LDAP applications and their policy.
-- See LDAP.md.
CREATE TABLE ldap_apps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  -- Branch RDN and service-account CN: ou=<slug>,<base> and cn=<slug>,ou=services,<base>.
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  -- SHA-256 of the service-account secret. High-entropy and generated, so a
  -- fast hash is correct here, as for api_keys.
  secret_hash TEXT NOT NULL,
  secret_prefix TEXT NOT NULL,
  -- JSON array of group ids whose members may bind and are visible to this
  -- app. '[]' = every active user.
  user_group_ids TEXT NOT NULL DEFAULT '[]',
  -- JSON array of group ids this app can see as group entries. '[]' = all.
  exposed_group_ids TEXT NOT NULL DEFAULT '[]',
  -- 'password' | 'otp_if_enrolled' | 'otp_required'. Section 13.
  mfa_mode TEXT NOT NULL DEFAULT 'otp_if_enrolled'
    CHECK (mfa_mode IN ('password', 'otp_if_enrolled', 'otp_required')),
  -- Show disabled users (userAccountControl 514) so syncing apps can deactivate them.
  include_disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

INSERT INTO idp_settings (key, value, updated_at) VALUES
  ('ldap_enabled', 'false', CURRENT_TIMESTAMP),
  ('ldap_base_dn', '', CURRENT_TIMESTAMP),           -- '' = derive from default domain
  ('ldap_hostname', '', CURRENT_TIMESTAMP),          -- e.g. ldap.example.com, for dnsHostName and UI snippets
  ('ldap_netbios_name', '', CURRENT_TIMESTAMP),      -- '' = uppercased first label of the default domain
  ('ldap_unscoped_bind_app', '', CURRENT_TIMESTAMP), -- slug, or '' = deny unattributed user binds (section 9)
  ('ldap_domain_sid', '', CURRENT_TIMESTAMP),        -- generated on first enable (section 11)
  ('ldap_guid_namespace', '', CURRENT_TIMESTAMP),    -- generated on first enable (section 11)
  ('ldap_posix_uid_base', '10000', CURRENT_TIMESTAMP),
  ('ldap_posix_gid_base', '20000', CURRENT_TIMESTAMP),
  ('ldap_posix_default_gid', '100', CURRENT_TIMESTAMP),
  ('ldap_posix_shell', '/bin/bash', CURRENT_TIMESTAMP),
  ('ldap_posix_home', '/home/{username}', CURRENT_TIMESTAMP),
  ('ldap_idle_timeout_minutes', '15', CURRENT_TIMESTAMP),
  ('ldap_otp_rebind_seconds', '120', CURRENT_TIMESTAMP);
```

Add an `LdapAppRow` type to `src/lib/types.ts`. Reuse `randomToken` and
`sha256Hex` from `src/lib/tokens.ts` for secrets. Use a `flareid_ldap_` prefix
so leaked secrets are recognisable, mirroring `KEY_PREFIX` in `api-keys.ts`.

**Group visibility.** "Super Admins" is an ordinary group and appears in
`exposed_group_ids` only if an admin chooses it. The default `'[]'` (all
groups) includes it. Show a hint in the UI: exposing it lets the app grant
admin rights based on FlareID admin status, which is usually unintended.

---

## 8. Entries and attributes

Attribute names are case-insensitive on input. Return them in the canonical
case shown here. All string values are UTF-8. Timestamps use GeneralizedTime
`YYYYMMDDHHMMSS.0Z`, converted from the ISO strings in `created_at` /
`updated_at`.

### User entry (`uid=<username>,ou=people,ou=<slug>,<base>`)

| LDAP attribute | Source | Notes |
|---|---|---|
| `objectClass` | - | `top`, `person`, `organizationalPerson`, `inetOrgPerson`, `user` (AD), `posixAccount`, `shadowAccount` |
| `uid` | `username` | |
| `cn` | `display_name` | |
| `displayName` | `display_name` | |
| `givenName` | `given_name` | Omit if empty |
| `sn` | `family_name` | `person` requires `sn`; if empty, use `display_name` |
| `mail` | `email ?? upn` | Same rule as `recipientFor` in `src/lib/email.ts` |
| `userPrincipalName` | `upn` | AD |
| `sAMAccountName` | `username` | AD |
| `title` | `job_title` | Omit if empty |
| `department` | `department` | Omit if empty |
| `employeeNumber` | `employee_number` | Omit if empty |
| `employeeType` | `employment_type` | Omit if empty |
| `l` | `location` | Omit if empty |
| `manager` | DN of the user whose `external_id = manager_external_id` | Only if the manager is visible to this app |
| `memberOf` | DNs of visible groups the user is in (explicit + dynamic) | Returned for `*`, as AD does |
| `entryUUID` | `external_id` | RFC 4530 |
| `objectGUID` | `external_id` as AD binary GUID | Section 11 |
| `objectSid` | domain SID + RID | Section 11 |
| `objectCategory` | `CN=Person,CN=Schema,CN=Configuration,<base>` | Section 11 |
| `sAMAccountType` | `805306368` | AD normal user account |
| `userAccountControl` | `512` active, `514` disabled | AD |
| `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`, `gecos` | Section 12 | POSIX |
| `whenCreated` / `createTimestamp` | `created_at` | |
| `whenChanged` / `modifyTimestamp` | `updated_at` | |
| `distinguishedName` | the entry DN | AD |

**Custom attributes.** Expose a user's `custom_attributes` keys that are valid
LDAP attribute names (`^[A-Za-z][A-Za-z0-9-]{0,63}$`) and don't collide with
the names above, as single-valued strings. Advertise them in the subschema as
`directoryString` / `caseIgnoreMatch`. Skip the rest silently.

**Never returned, under any attribute selection:** `userPassword`,
`password_hash`, `password_salt`, `totp_secret`, `totp_last_counter`,
`unicodePwd`, `scim_id`. A filter on `userPassword` evaluates to Undefined.

### Group entry (`cn=<name>,ou=groups,ou=<slug>,<base>`)

| LDAP attribute | Source | Notes |
|---|---|---|
| `objectClass` | - | `top`, `groupOfNames`, `groupOfUniqueNames`, `posixGroup`, `group` (AD) |
| `cn` | `name` | |
| `description` | `description` | Omit if empty |
| `member` | DNs of visible members | Effective membership: `group_members`, or the rule for a dynamic group |
| `uniqueMember` | same DNs | vCenter's OpenLDAP mode requires `groupOfUniqueNames`/`uniqueMember` |
| `memberUid` | usernames of visible members | RFC 2307 |
| `gidNumber` | `ldap_posix_gid_base + groups.id` | |
| `sAMAccountName` | `name` | AD |
| `groupType` | `-2147483646` | AD global security group |
| `sAMAccountType` | `268435456` | AD |
| `objectCategory` | `CN=Group,CN=Schema,CN=Configuration,<base>` | |
| `entryUUID` / `objectGUID` | UUIDv5(`ldap_guid_namespace`, `"group:" + id`) | Stable across renames |
| `objectSid` | domain SID + group RID | |
| `distinguishedName` | the entry DN | |

Presenting `groupOfNames` and `groupOfUniqueNames` together is technically two
structural classes. It is a deliberate deviation, harmless to every client
listed in section 2. Keep a comment in `entries.ts` saying so.

Empty groups have no `member` value. That is schema-invalid for
`groupOfNames`, but it is what clients handle best for a virtual directory.

### Containers

`dc=example,dc=com` (`top`, `domain`, `dcObject`, `dc`), `ou=<slug>`,
`ou=people`, `ou=groups` (`top`, `organizationalUnit`, `ou`). They exist so
that base and one-level searches on them behave. `ou=services` and its
children are **never** returned by search: a service account is a credential,
not a directory object.

### Attribute selection (RFC 4511 4.5.1.8)

- Empty list or `*`: all user attributes from the tables above.
- `+`: operational attributes (`entryUUID`, `entryDN`, `createTimestamp`,
  `modifyTimestamp`, `subschemaSubentry`, `hasSubordinates`).
- `1.1`: no attributes.
- Named attributes: those only. Unknown names are ignored (not an error).
- `typesOnly`: names without values.
- Attribute options: `;binary` is accepted and ignored. `;range=` is handled
  in phase 2 (section 11). Unknown options mean the attribute is not returned.

---

## 9. Bind

### Name forms

Accepted, tried in this order:

1. **A DN in our tree.**
   - `cn=<slug>,ou=services,<base>`: a **service bind** for that app.
   - `uid=<username>,ou=people,ou=<slug>,<base>`: a **user bind**, attributed
     to app `<slug>`.
   - Any other DN in our tree, or `uid=<username>,ou=people,<base>` without a
     branch: `invalidCredentials`.
2. **UPN**: contains `@` and no `=`. Resolve with `getUserByLoginIdentifier`
   (`src/lib/db.ts`).
3. **Down-level logon name**: `NETBIOS\user`. The prefix must match
   `ldap_netbios_name`, case-insensitively. Resolve `user` as a username.
4. **Bare username**: no `@`, `=` or `\`. Resolve as a username. AD itself
   rejects this, but enough apps send it that FlareID's own login accepts it.

**App attribution for forms 2-4.** These names carry no app. Attribute the
bind to `state.app`, which is set by a service bind on the same connection and
**stays set** when that connection rebinds as a user (Grafana, net-ldap's
`bind_as` and others search as the service account, then rebind as the user on
the same connection). If `state.app` is null, use the app named by
`ldap_unscoped_bind_app`. If that is empty (the default), fail the bind with
`invalidCredentials` and audit it with reason `unattributed`.

### Anonymous and unauthenticated binds

- **Anonymous** (empty name and empty password): allowed. The only thing it
  can read is the root DSE (and `cn=Subschema`). Every other search returns
  `insufficientAccessRights` (50), not an empty result, so misconfiguration is
  obvious.
- **Unauthenticated** (non-empty name, empty password): **always** fail with
  `unwillingToPerform` (53), per RFC 4513 5.1.2. Many apps treat a successful
  empty-password bind as a login. This is the single most important bind rule.

### Service bind

1. Look up the app by slug. It must exist and have `revoked_at IS NULL`.
2. Compare `sha256Hex(password)` with `secret_hash` in constant time.
3. Rate-limit with `recordRateAttempt(env, "ldap:svc:<slug>", 20, 15)` before
   comparing, and on the per-IP bucket if the IP is known.
4. On success: `state.bound = { kind: "service", app }`, `state.app = app`,
   update `last_used_at` (via `ctx.waitUntil`, at most once a minute per app).

### User bind

This mirrors `POST /login` in `src/routes/login.ts`. Reuse its helpers rather
than copying the logic:

1. If `ldap_enabled` is false, or `isSetupCompleted` is false: Notice of
   Disconnection. There is no admin exception for LDAP.
2. Resolve the user from the name form. Resolve the app (above).
3. `recordLoginAttempt(env, loginRateKey(identifier, user), ip)` **before**
   verifying. If over budget: `invalidCredentials`, audit
   `ldap.bind.rate_limited`. This shares the account bucket with web sign-in
   deliberately: LDAP must not double an attacker's budget. If the IP is
   unknown, pass a constant such as `"ldap:unknown"` so the IP bucket is
   shared and still caps sprays. See section 20 on client IP.
4. Usable means `user.status === "active"`, `!user.password_hash.startsWith("!")`,
   the app is not revoked, and the user is a member of one of
   `app.user_group_ids` (or the list is empty).
5. Split password and OTP according to the app's `mfa_mode` (section 13).
6. Verify the password with `verifyPassword`. For unusable or unknown users,
   verify against the dummy hash, exactly like `login.ts`, so timing doesn't
   reveal which accounts exist. Extract `dummyPasswordHash` from `login.ts`
   into `src/lib/password.ts` so both can share it.
7. Verify the OTP if required (section 13).
8. On success: `clearLoginAttempts`, `upgradePasswordHashIfNeeded`,
   `state.bound = { kind: "user", userId, app }`, audit `ldap.bind.success`.
9. On any failure, return the **same** result: `invalidCredentials` (49). Use
   diagnosticMessage
   `80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data 52e, v4563`.
   That is AD's "bad credentials" text, which Spring Security's AD provider and
   Atlassian parse. Always use sub-code `52e`, never `533` (disabled) or `775`
   (locked), because those reveal account state. Audit `ldap.bind.failed` with
   the real reason in `details`.

**Bind resets state.** Per RFC 4511 4.2.1, a bind (successful or not) discards
the previous authentication, so a failed bind leaves the connection anonymous.
`state.app` is kept, because it records who opened the connection, not who is
authenticated.

**Re-validation.** On every operation from a user-bound connection, re-read
`users.status`. If the user is now disabled, or no longer in
`app.user_group_ids`, drop to anonymous and return
`insufficientAccessRights`. For service-bound connections, re-check
`revoked_at` at most every 60 seconds. If revoked, send a Notice of
Disconnection.

---

## 10. Search, Compare and filters

### Authorisation

| Bound as | May search |
|---|---|
| anonymous | Root DSE and `cn=Subschema` only |
| service (app X) | Everything in `ou=X,<base>`, plus the base DN entry and the root DSE |
| user (app X) | Their own entry, and the group entries they belong to (with `member`/`uniqueMember`/`memberUid` reduced to themselves) |

**Confining searches to the branch.** A search whose base is above the app's
branch (the naming context, as AD-mode clients usually use) is evaluated as if
the base were the branch, but the scope semantics are kept: a one-level search
on the naming context returns only `ou=X`. A base outside our tree returns
`noSuchObject` (32) with `matchedDN` set to the deepest existing ancestor. A
base inside another app's branch returns `noSuchObject` too, so other branches
are invisible rather than forbidden.

### The directory snapshot

Search evaluates filters in memory over a snapshot:

```ts
interface DirectorySnapshot {
  users: UserRow[];                  // SELECT * FROM users
  groups: GroupRow[];                // SELECT * FROM groups
  explicit: Map<number, number[]>;   // group_id -> user_ids, from group_members
  dynamic: Map<number, number[]>;    // evaluated with parseRule/userMatchesRule, in memory
}
```

- Build it in three queries, using `D1Database.batch`. Do **not** call
  `resolveGroupMemberUserIds` per group: it reloads every user for every
  dynamic group.
- Cache it on the connection for 30 seconds. SSSD issues bursts of searches,
  and this keeps a burst to one D1 round trip.
- Derive the app's view from the snapshot: visible users (active, or all if
  `include_disabled`; and in `user_group_ids`), visible groups
  (`exposed_group_ids`), and membership restricted to visible users.
- **Push-down.** For the most common shape, an equality on `uid`,
  `sAMAccountName`, `mail`, `userPrincipalName` or `cn`, optionally ANDed with
  `objectClass`/`objectCategory` terms, skip the full snapshot and query that
  one user directly with bound parameters. Then load only that user's group
  memberships. That serves the per-login search cheaply. Everything else uses
  the snapshot.
- Scale ceiling: this is fine into the low tens of thousands of users. Note the
  ceiling in docs/architecture.md, alongside ROADMAP item 29.

### Filters (RFC 4511 4.5.1.7, RFC 4515 for tests)

Implement three-valued logic (TRUE / FALSE / Undefined). Undefined comes from
an unknown attribute, an inappropriate matching rule, or a malformed assertion.
`NOT Undefined = Undefined`. AND and OR follow the RFC truth tables. Only TRUE
returns an entry.

| Filter | Semantics |
|---|---|
| `and`, `or`, `not` | As specified. Empty `and` = TRUE, empty `or` = FALSE. |
| `equalityMatch` | caseIgnoreMatch for directory strings; DN normalised equality for DN-valued attributes (`member`, `memberOf`, `manager`, `uniqueMember`); integer equality for numeric attributes; `objectClass` matches any of the entry's classes, case-insensitively. |
| `substrings` | caseIgnoreSubstringsMatch: initial / any* / final, in order. |
| `greaterOrEqual`, `lessOrEqual` | Integers numerically; GeneralizedTime by instant; strings by case-folded code-point order. |
| `present` | Attribute has at least one value. `(objectClass=*)` is always TRUE. |
| `approxMatch` | Treat as equality. |
| `extensibleMatch` | Only the AD rules in section 11 and `caseIgnoreMatch` / `caseExactMatch` by name or OID. `dnAttributes=TRUE`: Undefined. Anything else: Undefined. |

Limits: filter nesting depth at most 32, at most 256 nodes, assertion values
at most 4 KiB. Exceeding any of them returns `unwillingToPerform` (53).

`objectCategory` equality accepts the full DN **or** the short names `person`,
`user` (for users) and `group`. AD resolves short names, and AD-mode filters
like `(&(objectCategory=person)(objectClass=user)(sAMAccountName=alice))` rely
on that.

### Size, time and paging

- **Server size limit**: 1000 entries per response (AD's MaxPageSize).
  Effective limit = min(client `sizeLimit` if non-zero, 1000). Without the
  paged-results control, send up to the limit, then `SearchResultDone` with
  `sizeLimitExceeded` (4).
- **Paged Results (RFC 2696)**: the control value is
  `SEQUENCE { size INTEGER, cookie OCTET STRING }`.
  - First page: compute the ordered list of matching entry keys (stable order:
    users by `id`, then groups by `id`, containers first), store it in
    `state.pagedSearches` under a random 16-byte cookie, return the first
    `min(size, 1000)` entries plus a response control carrying the cookie.
    `size` in the response is an estimate of the total, or 0.
  - Next pages: look the cookie up. It is valid only on the same connection
    and with the same base, scope and filter; otherwise `unwillingToPerform`.
  - Last page: response control with an empty cookie; delete the state.
  - `size = 0` with a cookie means abandon: delete the state and return
    `success` with no entries.
  - At most 8 paged searches per connection; evict the oldest.
- **timeLimit**: honour it if non-zero, capped at 30 seconds. Return
  `timeLimitExceeded` (3).
- `derefAliases`: ignore; there are no aliases.

### Compare

Compare evaluates `attribute = value` against one entry, with the same
authorisation and matching rules as an equality filter: `compareTrue` (6),
`compareFalse` (5), `noSuchObject` (32), or `undefinedAttributeType` (17) for
attributes the entry type doesn't have. Compare on `userPassword` returns
`unwillingToPerform` (53). It must never be usable as a password oracle.

---

## 11. Active Directory compatibility

Everything in this section exists so that apps and devices configured in "AD
mode" work without reconfiguration.

**Bind names**: `NETBIOS\user` and UPN are covered in section 9.
`ldap_netbios_name` defaults to the uppercased first label of the default
domain (`example.com` -> `EXAMPLE`). Ricoh and Xerox MFPs require
`Domain\Username`.

**Global Catalog port 3269 (LDAPS)** behaves identically to 636. It is a
second Spectrum app pointing at the same Worker. Ricoh, and some
AD-configured apps, default to it. Port 3268 (GC with StartTLS) cannot be
served; see section 19.

**objectGUID.** Binary, 16 bytes, AD byte order: the first three UUID fields
little-endian, the last eight bytes as written. For
`00112233-4455-6677-8899-aabbccddeeff`:
`33 22 11 00 55 44 77 66 88 99 aa bb cc dd ee ff`. Users: `external_id`.
Groups: UUIDv5 of `"group:" + id` under `ldap_guid_namespace`; SHA-1 is in
Web Crypto. An equality filter on `objectGUID` may arrive as raw bytes, or as
the escaped string `\33\22\11...`. Both must match.

**objectSid.** Binary SID: revision `1`, sub-authority count, 6-byte
big-endian identifier authority `5`, then 32-bit **little-endian**
sub-authorities. Domain SID `S-1-5-21-a-b-c`, with `a`, `b` and `c` random
32-bit values generated once when LDAP is first enabled and stored in
`ldap_domain_sid`. RIDs: users `10000 + users.id`, groups
`100000000 + groups.id` (AD RIDs are 30-bit). SQLite `AUTOINCREMENT` never
reuses ids, so RIDs, POSIX ids and UUIDv5s are stable.

**Matching rules** (extensibleMatch):

| OID | Name | Implement as |
|---|---|---|
| `1.2.840.113556.1.4.803` | LDAP_MATCHING_RULE_BIT_AND | `(attr & value) == value` on integers. Used as `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` to exclude disabled accounts. |
| `1.2.840.113556.1.4.804` | LDAP_MATCHING_RULE_BIT_OR | `(attr & value) != 0` |
| `1.2.840.113556.1.4.1941` | LDAP_MATCHING_RULE_IN_CHAIN | **Plain DN equality.** FlareID groups are flat by design (ROADMAP, "Explicitly out of scope"), so transitive membership *is* direct membership. Grafana, GitLab and Jenkins docs all use this rule for nested AD groups. |

**Ranged retrieval** (phase 2): when a client requests `member;range=L-H`,
return `member;range=L-H` with that slice, and `member;range=L-*` on the last
slice. Without a range option, return all values. AD caps at 1500, and
clients only use ranges when told to.

**Bind diagnostic**: always `data 52e` (section 9).

---

## 12. POSIX (Linux / SSSD) support

The attributes are on every user and group (section 8). Apps that don't use
them ignore them, so there is no per-app toggle.

| Attribute | Value |
|---|---|
| `uidNumber` | `ldap_posix_uid_base + users.id` |
| `gidNumber` (user) | `ldap_posix_default_gid` (default 100, `users`) |
| `homeDirectory` | `ldap_posix_home` with `{username}` substituted |
| `loginShell` | `ldap_posix_shell` |
| `gecos` | `display_name`, ASCII-folded |
| `gidNumber` (group) | `ldap_posix_gid_base + groups.id` |
| `memberUid` (group) | usernames (RFC 2307), alongside `member` (RFC 2307bis) |

Document a reference `sssd.conf` in the admin UI's app page:

```ini
[domain/flareid]
id_provider = ldap
auth_provider = ldap
ldap_uri = ldaps://ldap.example.com
ldap_search_base = ou=linux,dc=example,dc=com
ldap_default_bind_dn = cn=linux,ou=services,dc=example,dc=com
ldap_default_authtok = <secret>
ldap_schema = rfc2307bis
ldap_tls_reqcert = demand
cache_credentials = true
enumerate = false
```

SSSD caches credentials, so the app's `mfa_mode` should be `password` (see
section 13). The UI should say so when the app is named or described as
Linux/SSSD.

`sshPublicKey` (`ldapPublicKey`) is out of scope until FlareID stores SSH keys.
When it does, add it here.

---

## 13. MFA over LDAP

LDAP has no second-factor step, so the factor travels in the password field.
This is the convention Okta's LDAP Interface established.

**Format**: `<password>,<6-digit code>`. Split on the **last** comma, and only
when the part after it is exactly six digits.

| `mfa_mode` | User has MFA enrolled | User not enrolled |
|---|---|---|
| `password` | Password only. The whole field is the password. | Password only |
| `otp_if_enrolled` (default) | Password **and** OTP required | Password only, unless global `require_mfa` is on, in which case fail (reason `mfa_enrollment_required`) |
| `otp_required` | Password **and** OTP required | Fail (reason `mfa_enrollment_required`) |

When an OTP is required but the field doesn't have the `,123456` shape, fail
with `invalidCredentials` (reason `otp_missing`). Do **not** fall back to
treating the whole field as the password.

**Verification**: `matchTotpCounter` then `claimTotpCounter`
(`src/lib/totp.ts`), so replay protection matches the web flow. Rate-limit the
OTP step with `recordMfaAttempt` / `clearMfaAttempts`. Backup codes are not
accepted over LDAP.

**The re-bind problem.** Many apps bind twice with the same credentials within
seconds, for example a test bind followed by the real one, or a search
connection followed by an auth connection. The second bind would fail, because
the TOTP counter has been claimed. So after a successful OTP bind, store
`sha256Hex(app.id + ":" + user.id + ":" + fullCredentialField)` in
`SESSIONS_KV` with TTL `ldap_otp_rebind_seconds` (default 120). A later bind
whose hash matches skips the OTP check, but still verifies the password and
all of step 4 in section 9. The trade-off, documented in the UI: within that
window, the exact same credential string can be replayed against the same app
only.

Push approval is out of scope: FlareID has no push factor.

---

## 14. Security requirements

Non-negotiable. Write a test for each.

1. **TLS only.** Never create a Spectrum app with `tls: "off"`. The Worker
   cannot tell whether a connection came through TLS, so this is enforced in
   deployment (section 16) and nowhere else. Say so in the docs.
2. **Unauthenticated bind rejected** (section 9).
3. **Generic bind failures** with uniform timing: dummy hash, and the same
   result code and diagnostic for every reason.
4. **Shared lockout** with web sign-in (section 9, step 3).
5. **Per-connection caps**: after 5 failed binds on one connection, send a
   Notice of Disconnection and close. Max PDU 64 KiB. Filter limits as in
   section 10. At most 100 requested attributes. Idle timeout
   `ldap_idle_timeout_minutes`, after which send a Notice of Disconnection.
6. **No secrets in output or logs.** Section 8's never-returned list. Never log
   bind passwords or request bytes; log message types and result codes only.
7. **No writes.** Every modifying operation returns `unwillingToPerform`.
8. **Re-validation** of bound identities on each operation (section 9).
9. **Service secrets**: generated (24+ bytes), shown once, stored as SHA-256,
   rotatable, revocable. Rotation replaces the hash immediately. There is no
   overlap window in v1; say so in the UI.
10. **CPU.** A scrypt verify costs about 100 ms of CPU. A long-lived connection
    serving many binds accumulates CPU inside one `connect()` invocation; see
    section 20. On `PASSWORD_HASHER=pbkdf2` (Workers Free plan) LDAP still
    works, but recommend the paid plan in the docs.
11. **Disabled LDAP**: when `ldap_enabled` is false, every new connection gets
    a Notice of Disconnection immediately, and open connections get one on
    their next operation.
12. **Network restriction** is Spectrum's job: set `ip_firewall: true` on the
    Spectrum apps and document allowlisting with IP Access Rules. FlareID does
    not attempt IP allowlists itself unless section 20 shows that
    `remoteAddress` is reliable.

---

## 15. Admin UI, provisioning API, audit

### Admin UI

Follow the existing Integrations section (`/admin/integrations/oidc`,
`/admin/integrations/saml` in `src/routes/admin.ts`). Add:

- **`/admin/integrations/ldap`**: the list of LDAP apps, plus the LDAP settings
  card (enable, hostname, base DN, NetBIOS name, unscoped-bind app, POSIX
  bases, idle timeout, OTP re-bind window). Add a summary card on the
  `/admin/integrations` overview.
- **Create app**: name, slug, user groups, exposed groups, MFA mode, include
  disabled. On create, show **once**:
  - Server: `ldaps://<ldap_hostname>:636` (and `:3269`)
  - Bind DN: `cn=<slug>,ou=services,<base>`
  - Secret
  - Base DN: `ou=<slug>,<base>`
  - User search base `ou=people,ou=<slug>,<base>`, group search base
    `ou=groups,ou=<slug>,<base>`
  - User filter, generic: `(&(objectClass=inetOrgPerson)(uid=%s))`; AD mode:
    `(&(objectCategory=person)(sAMAccountName=%s))`
  - Collapsible snippets for Grafana `ldap.toml`, `sssd.conf`, GitLab
    `gitlab.rb`, Jenkins, and `ldapsearch`.
- **App page**: edit policy, rotate secret, revoke, last used, and a link to the
  log filtered to `ldap.*` for this app.

### Provisioning API

Add to `src/routes/api.ts` and document in `docs/api.md`, in the same style as
SAML service providers. It must be idempotent: upsert by `slug`.

| Endpoint | Scope | Notes |
|---|---|---|
| `GET /api/v1/ldap/apps` | `directory:read` | Never returns secrets |
| `POST /api/v1/ldap/apps` | `clients:write` | Upsert by slug; returns `secret` only when the app is created |
| `POST /api/v1/ldap/apps/{slug}/rotate` | `clients:write` | Returns the new secret |
| `DELETE /api/v1/ldap/apps/{slug}` | `clients:write` | Sets `revoked_at` |
| `GET /api/v1/ldap/settings`, `POST /api/v1/ldap/settings` | `directory:read` / `settings:write` | |

Group references in the API are by **name**, as elsewhere in the import API,
and are resolved to ids on write.

### Audit actions

`ldap.bind.success`, `ldap.bind.failed` (with `details.reason`: `bad_password`,
`unknown_user`, `disabled`, `no_usable_password`, `not_in_app_groups`,
`otp_missing`, `otp_invalid`, `mfa_enrollment_required`, `unattributed`,
`app_revoked`), `ldap.bind.rate_limited`, `ldap.service_bind.failed`,
`ldap.app.created`, `ldap.app.updated`, `ldap.app.secret_rotated`,
`ldap.app.revoked`, `ldap.settings.updated`. Add an `ldap` action family to the
log filters.

`logAudit` takes a `Request` for the IP and user agent. Add a sibling that
takes `{ ip, userAgent }` directly; for LDAP, user agent = `ldap:<app slug>`.
Write audit rows with `ctx.waitUntil` so they don't add latency to binds.
**Do not audit searches**: SSSD alone would flood the table. Count them in
Workers logs instead (one structured line per connection close: ops by type,
results by code, duration).

---

## 16. Deployment

1. **Worker**: add `connect` to the default export in `src/index.ts`. Check
   whether `connect()` needs a newer `compatibility_date` or a flag than the
   current `2025-04-01`. If it does, bump it in a separate commit and run the
   full test suite.
2. **Spectrum beta**: the account must be enrolled in the Worker-origin beta.
3. **Edge certificate**: Universal SSL is **not** compatible with Spectrum
   (<https://developers.cloudflare.com/spectrum/reference/limitations/>). Use an
   Advanced certificate or a custom certificate covering `ldap.<zone>`. Prefer a
   custom certificate uploaded with **Legacy** client support (non-SNI): some
   LDAP client stacks (older OpenLDAP builds, embedded devices) don't send SNI.
4. **Spectrum apps**, one per port:

   ```json
   {
     "protocol": "tcp/636",
     "dns": { "type": "CNAME", "name": "ldap.example.com" },
     "traffic_type": "worker",
     "origin_worker_id": "flareid-idp",
     "tls": "flexible",
     "ip_firewall": true,
     "edge_ips": { "type": "dynamic", "connectivity": "all" }
   }
   ```

   And the same with `"protocol": "tcp/3269"`. Never `tls: "off"`.
5. **Not in `npm run deploy`.** Spectrum needs the beta and a suitable plan, so
   `scripts/deploy.mjs` must not try to create it. Document the steps in a new
   `docs/ldap.md` (operator guide: setup, client snippets, troubleshooting) and
   link it from the README. An optional `scripts/ldap-spectrum.mjs` that calls
   the Spectrum API is welcome.
6. **Docs to update**: README (protocols list), docs/architecture.md (request
   path gains a `connect` entry; a storage row for `ldap_apps`), docs/api.md,
   CHANGELOG.md `[Unreleased]`, and ROADMAP.md (add LDAP as done; add StartTLS
   and the items in section 19 as future work).

---

## 17. Testing

Tests run in the Workers runtime against the real migrations, like the rest of
the suite (`npm test`, `npm run typecheck`).

1. **BER unit tests** (`test/ldap-ber.test.ts`): round-trip encode/decode;
   long-form lengths; reject indefinite lengths, truncated TLVs, oversize
   lengths, and nesting beyond a limit. Include **real captures**: hex of an
   `ldapsearch -x` bind, a search with the paged control, and a WhoAmI,
   captured once from OpenLDAP and checked in as fixtures.
2. **Filter tests**: parse RFC 4515 strings in tests (a test-only parser is
   fine) into the BER filter. Evaluate against fixture entries, covering
   three-valued logic, substrings, `objectCategory` short names, the three AD
   matching rules, `objectGUID` as raw and escaped bytes, and the limits.
3. **Protocol integration tests** (`test/ldap.test.ts`): drive
   `LdapConnection` through a `TransformStream` pair (no real socket), seeded
   through the provisioning API helpers in `test/helpers.ts`. At minimum:
   - root DSE anonymously; anything else anonymously -> 50
   - service bind good/bad/revoked; user bind by DN, UPN, `NETBIOS\user`, bare
     username
   - **empty-password bind -> 53**
   - disabled user, `!` hash user, user outside `user_group_ids` -> 49, same
     diagnostic
   - shared lockout: N failed LDAP binds lock web login, and vice versa
   - branch confinement: app A cannot see or bind into app B's branch
   - `exposed_group_ids` filtering, and membership restricted to visible users
   - dynamic group membership in `memberOf` and `member`
   - paged search across 2,500 users; cookie on another connection is rejected
   - sizeLimitExceeded without paging
   - Compare true/false; Compare on `userPassword` -> 53
   - OTP modes, replay rejected, re-bind window honoured and scoped to the app
   - write operations -> 53; StartTLS -> 2; SASL -> 7
   - idle timeout and failed-bind cap produce a Notice of Disconnection
   - user re-validation after disable mid-connection
4. **Real-client compatibility** (manual, before release; record results in
   docs/ldap.md): `ldapsearch`/`ldapwhoami` (OpenLDAP), Python `ldap3`, Java
   JNDI, Apache Directory Studio, Grafana, Jenkins, GitLab, SSSD on Ubuntu and
   RHEL, and one firewall (PAN-OS or FortiGate) if available.
5. **Local dev bridge** (optional, dev-only): `wrangler dev` cannot accept TCP.
   A small dev Worker with a service binding to FlareID can accept a WebSocket
   and pipe it to `env.IDP.connect("ldap")`. A local Node script
   (`scripts/ldap-bridge.mjs`, listening on `127.0.0.1:1389`) pipes TCP to that
   WebSocket. Real clients can then run
   `ldapsearch -H ldap://127.0.0.1:1389 ...` against a dev instance. Plaintext
   is fine on loopback only; the script must refuse to bind anything else.

---

## 18. Phasing

**Phase 1: usable for most apps**
- BER, framing, LDAPMessage, result codes, Notice of Disconnection
- Bind: service, user (DN / UPN / `NETBIOS\user` / bare), anonymous,
  unauthenticated rejection, lockout, re-validation
- Search: scopes, filters (including the AD matching rules and
  `objectCategory`), attribute selection, size limits, paged results,
  push-down, snapshot cache
- Compare, Abandon, Unbind, WhoAmI
- Root DSE, `cn=Subschema`
- User/group entries with inetOrgPerson, groupOfNames/UniqueNames, `memberOf`,
  and the AD attributes (`sAMAccountName`, `userPrincipalName`,
  `objectGUID`, `objectSid`, `userAccountControl`, ...)
- `ldap_apps`, settings, admin UI, provisioning API, audit
- Ports 636 and 3269
- Tests (sections 17.1-17.3), docs

**Phase 2: Linux and MFA**
- POSIX attributes and the SSSD snippet
- OTP-in-password MFA with the re-bind window
- Ranged retrieval
- Real-client compatibility run (section 17.4)

**Phase 3: optional, only on demand**
- StartTLS on 389 via a WASM TLS stack (for example rustls) inside the Worker,
  behind a Spectrum app with `tls: "off"`. This recovers Meraki and Odoo. The
  same component would serve RADIUS EAP-TTLS later.
- Server-side sort control
- Password Modify extended operation (FlareID's password policy applies)

---

## 19. Explicitly out of scope

- StartTLS and plaintext LDAP on 389 (until phase 3), including Global Catalog
  3268
- SASL of any kind: GSSAPI/Kerberos, DIGEST-MD5, EXTERNAL, NTLM
- Client-certificate authentication
- Writes: Add, Modify, Delete, ModifyDN, schema changes
- Referrals, aliases, replication (syncrepl), persistent search, DirSync
- `tokenGroups`, nested groups (FlareID is flat by design)
- SMB/CIFS authentication, NT hashes, `sambaNTPassword`
- Domain join, Group Policy, Windows logon
- LDAPv2

---

## 20. Open questions to verify on the platform

Verify these once the Spectrum Worker-origin beta is enabled, and record the
answers here.

1. **Client IP.** Does `socket.opened` resolve with `remoteAddress` set to the
   real client IP for Spectrum-originated connections? If yes, use it for the
   IP rate-limit bucket and the audit `ip`, and consider per-app CIDR
   allowlists. If no, keep the shared `ldap:unknown` bucket and rely on
   Spectrum IP Access Rules.
2. **CPU and duration limits** for a long-lived `connect()` invocation: is the
   CPU limit per invocation (so a connection doing hundreds of scrypt binds
   could hit it)? Does `limits.cpu_ms` in wrangler.jsonc apply? Is there a
   maximum connection duration? If CPU is per invocation, cap binds per
   connection (for example 200) and send a Notice of Disconnection before the
   limit; clients will reconnect.
3. **Billing** for connection duration during and after the beta.
4. **Compatibility date / flags** required for `connect()`.
5. **Plan and ports**: confirm 636 and 3269 are allowed for the zone's plan.
6. **Non-SNI clients** actually receive the legacy custom certificate through
   Spectrum.
7. **Deploy behaviour**: confirm that open connections are closed, not hung,
   when a new Worker version deploys, so clients reconnect promptly.

---

## 21. Reference: wire constants

### LDAPMessage

```
LDAPMessage ::= SEQUENCE {                      -- 0x30
     messageID       INTEGER (0 .. 2^31-1),      -- 0x02
     protocolOp      CHOICE { ... },             -- tags below
     controls        [0] Controls OPTIONAL }     -- 0xA0
Control ::= SEQUENCE { controlType LDAPOID, criticality BOOLEAN DEFAULT FALSE, controlValue OCTET STRING OPTIONAL }
LDAPResult ::= resultCode ENUMERATED (0x0A), matchedDN OCTET STRING, diagnosticMessage OCTET STRING, referral [3] OPTIONAL
```

### Protocol op tags

| Op | Tag | Op | Tag |
|---|---|---|---|
| BindRequest | `0x60` | BindResponse | `0x61` |
| UnbindRequest | `0x42` | | |
| SearchRequest | `0x63` | SearchResultEntry | `0x64` |
| SearchResultDone | `0x65` | SearchResultReference | `0x73` |
| ModifyRequest | `0x66` | ModifyResponse | `0x67` |
| AddRequest | `0x68` | AddResponse | `0x69` |
| DelRequest | `0x4A` | DelResponse | `0x6B` |
| ModifyDNRequest | `0x6C` | ModifyDNResponse | `0x6D` |
| CompareRequest | `0x6E` | CompareResponse | `0x6F` |
| AbandonRequest | `0x50` | | |
| ExtendedRequest | `0x77` | ExtendedResponse | `0x78` |
| IntermediateResponse | `0x79` | | |

Bind authentication: simple `[0]` primitive `0x80`, sasl `[3]` constructed
`0xA3`. BindResponse `serverSaslCreds` `[7]` `0x87`. ExtendedRequest
`requestName` `0x80`, `requestValue` `0x81`. ExtendedResponse `responseName`
`0x8A`, `responseValue` `0x8B`.

SearchRequest: `baseObject` OCTET STRING, `scope` ENUMERATED (0 base, 1 one,
2 sub), `derefAliases` ENUMERATED, `sizeLimit` INTEGER, `timeLimit` INTEGER,
`typesOnly` BOOLEAN, `filter`, `attributes` SEQUENCE OF OCTET STRING.

### Filter tags

| Filter | Tag | Filter | Tag |
|---|---|---|---|
| and | `0xA0` | or | `0xA1` |
| not | `0xA2` | equalityMatch | `0xA3` |
| substrings | `0xA4` | greaterOrEqual | `0xA5` |
| lessOrEqual | `0xA6` | present | `0x87` (primitive) |
| approxMatch | `0xA8` | extensibleMatch | `0xA9` |

Substrings: `initial` `0x80`, `any` `0x81`, `final` `0x82`. extensibleMatch:
`matchingRule` `0x81`, `type` `0x82`, `matchValue` `0x83`, `dnAttributes`
`0x84`.

### Result codes used

| Code | Name | Code | Name |
|---|---|---|---|
| 0 | success | 17 | undefinedAttributeType |
| 1 | operationsError | 32 | noSuchObject |
| 2 | protocolError | 34 | invalidDNSyntax |
| 3 | timeLimitExceeded | 48 | inappropriateAuthentication |
| 4 | sizeLimitExceeded | 49 | invalidCredentials |
| 5 | compareFalse | 50 | insufficientAccessRights |
| 6 | compareTrue | 51 | busy |
| 7 | authMethodNotSupported | 52 | unavailable |
| 8 | strongerAuthRequired | 53 | unwillingToPerform |
| 12 | unavailableCriticalExtension | 80 | other |

### OIDs

| OID | Meaning |
|---|---|
| `1.2.840.113556.1.4.319` | Simple Paged Results control (RFC 2696) |
| `1.2.840.113556.1.4.473` | Server-side sort control (not supported) |
| `2.16.840.1.113730.3.4.2` | ManageDsaIT control (ignored) |
| `1.3.6.1.4.1.4203.1.11.3` | WhoAmI extended operation (RFC 4532) |
| `1.3.6.1.4.1.1466.20037` | StartTLS (not supported) |
| `1.3.6.1.4.1.4203.1.11.1` | Password Modify (not supported) |
| `1.3.6.1.4.1.1466.20036` | Notice of Disconnection (unsolicited, messageID 0) |
| `1.3.6.1.4.1.4203.1.5.1` | All operational attributes (`+`) feature |
| `1.2.840.113556.1.4.803` | AD bitwise AND matching rule |
| `1.2.840.113556.1.4.804` | AD bitwise OR matching rule |
| `1.2.840.113556.1.4.1941` | AD in-chain matching rule |

### Specifications

- RFC 4510-4519: LDAPv3 (4511 protocol, 4512 models, 4513 authentication,
  4514 DNs, 4515 filter strings, 4517 syntaxes/matching, 4519 schema)
- RFC 2696: Simple Paged Results
- RFC 4532: WhoAmI
- RFC 4530: entryUUID
- RFC 2798: inetOrgPerson
- RFC 2307 and draft-howard-rfc2307bis: POSIX schema
- MS-ADTS: section 5.1.1.1.1 (simple bind name forms), and its LDAP
  matching-rule and Global Catalog sections; MS-DTYP 2.4.2 (SID) and 2.3.4
  (GUID): AD behaviour
