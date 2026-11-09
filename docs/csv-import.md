# CSV import

Admin → Users → **Import CSV** takes a groups file, a users file, or both. The
browser parses them and sends the directory to the server in chunks of 50, so
a 10,000-row file works; each chunk goes through the same import as
`POST /api/v1/directory/import`. Running an import again updates rather than
duplicates: users are matched by `username`, groups by `name`.

`npm run test-data` writes a deterministic 10,000-person example to
`test-data/` (gitignored).

## groups.csv

| Column | Required | Notes |
|---|---|---|
| `name` | yes | |
| `description` | no | |
| `rule` | no | Empty for a static group; rule JSON for a dynamic one, e.g. `{"all":[{"field":"employment_type","op":"eq","value":"full_time"}]}` |

## users.csv

| Column | Notes |
|---|---|
| `username` | Required. The UPN is `username@<default domain>`. |
| `given_name`, `family_name`, `display_name` | |
| `email` | Contact address for invitations and recovery, when it is not the UPN. |
| `job_title`, `department`, `employee_number`, `hire_date`, `employment_status`, `employment_type`, `location` | |
| `manager` | Another row's `username`. Rows are reordered so managers are imported before their reports. |
| `status` | `active` or `disabled` (default `disabled`). |
| `groups` | Semicolon-separated static group names. Dynamic groups are ignored here: their membership is the rule. |
| `password` | Optional. Omitted: see below. |
| `schema` | Optional user schema name, e.g. `FlareID HR`. |
| anything else | Stored as a custom attribute of that name. |

**Passwords.** New users without a `password` get either no usable password
(the default: they activate from an invitation email or an admin reset, and
nothing is hashed, which keeps a large import fast) or the new-account
password setting from Admin → Security (each one is hashed, about 100 ms of
CPU apiece).

Super Admin membership cannot be granted from a CSV.

## Load test (10,000 users, 211 groups, local)

Groups imported in 0.2 s; users in 24 s (200 chunks of 50, slowest 0.2 s, no
errors). The users list, search, groups list, overview, integrations and log
pages all answered in under 70 ms with the full directory. A dynamic group
page lists the first 200 computed members. The static-membership picker on a
group page still lists every user, which is the known scale limit tracked as
roadmap item 29.
