# Attribute flows and mappings

**Admin → Flows** is where every attribute rule lives: what inbound writes (SCIM provisioning, federation sign-in) set on users, and what sign-ins and provisioning send back out. Each rule is a row — a **target** (the field it writes inbound, or the attribute/claim name it emits outbound) and an **expression** that computes the value.

## Channels

| Flow | Direction | Owner |
|---|---|---|
| SCIM provisioning (`scim-in`) | In | Global — all inbound SCIM writes |
| Federation sign-in (`jit`) | In | Global defaults, or per upstream IdP |
| SCIM push (`scim-out`) | Out | Per SCIM target |
| OIDC claims (`oidc`) | Out | Per client (adds/refines claims) |
| SAML attributes | Out | On each app's settings (attribute map / definitions) |

A flow with no rows of its own uses the channel's defaults: the seeded JIT claim lists, the standard SCIM attribute mapping, the default pushed SCIM document, and the standard OIDC claim set. Per-owner rows **replace** the defaults wholesale — they are never merged.

## Expressions

Expressions evaluate over the source document: the incoming SCIM body or the IdP's claims inbound; the user document outbound (`upn`, `username`, `display_name`, `given_name`, `family_name`, `email`, `name`, `id`, `job_title`, `department`, `manager`, `employee_number`, `hire_date`, `employment_status`, `employment_type`, `location`, `status`, `groups`, `emails`, `custom.<key>` and bare custom attribute names).

```
name.givenName                              paths (filters: emails[type eq "work"].value)
given_name + " " + family_name              concatenation
format("{0}.{1}@corp.com", lower(given_name), lower(family_name))
coalesce(preferred_username, email)         first non-empty
attr("http://schemas.../claims/upn")        attribute names outside the path grammar
lower(ascii(given_name + "." + family_name)) sign-in-name material
custom.cost_center                          schema attributes
```

The full function list is on the Flows page: string (`lower upper title capitalize trim concat join split substr left right replace replaceRe match ascii alnum initials word localpart domainpart format`), list (`len at take sort uniq reverse first`), logic (`eq ne gt lt ge le and or not in contains startsWith endsWith if select`), numbers (`add sub mul div mod int round min max`), plus `coalesce`, `attr`, `now`, `year`.

## Dynamic groups

Group rules accept an `expr` condition type that uses the same language as a predicate: pick **expr** as the operator in the rule builder and write e.g. `contains(department, "eng")` or `ge(hire_date, "2024-01-01")`. All conditions AND together as usual.

## Collision policy

When an inbound write would create a sign-in name or attach an email address that already belongs to another account:

- **Sign-in name** — append a counter (`jdoe2`, `jdoe3`…), evaluate a **pattern expression** over `{local, n, domain, email}` retried with n = 2, 3, 4…, or refuse.
- **Email address** — don't attach it (default), or refuse the write.

The policy applies to JIT provisioning and inbound SCIM alike.

## API

`GET/PUT /api/v1/mappings` manages rows per channel and owner (Super-Admin scope for writes; `schemas:read` for reads); `GET/PUT /api/v1/mappings/collisions` manages the collision policy. `/api/v1/scim/mappings` remains the delegable (`scim:write`) view of the inbound SCIM channel. See the [API reference](api.md).
