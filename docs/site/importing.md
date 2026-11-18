# Importing users

Import a whole directory from CSV files in **Users → Import CSV**. You can upload a groups file, a users file, or both. Running the same import again updates people rather than duplicating them: users are matched by `username` and groups by `name`.

## users.csv

| Column | Notes |
|---|---|
| `username` | **Required.** The UPN becomes `username@<default domain>`. |
| `given_name`, `family_name`, `display_name` | Names. |
| `email` | Where invitations and resets go, if not the UPN. |
| `job_title`, `department`, `employee_number`, `hire_date`, `employment_status`, `employment_type`, `location` | HR attributes. |
| `manager` | Another row's `username`. |
| `status` | `active` or `disabled`. The default is `disabled`. |
| `groups` | Static group names, separated by semicolons. |
| `password` | Optional. See below. |
| `schema` | Optional [schema](schemas.md) name. |
| any other column | Stored as a custom attribute with that name. |

## groups.csv

| Column | Notes |
|---|---|
| `name` | **Required.** |
| `description` | Optional. |
| `rule` | Empty for a static group, or a rule for a [dynamic group](groups.md#static-and-dynamic-groups). |

## Passwords

People imported without a `password` get no usable password by default. They activate their account from an [invitation](users.md#add-a-user) or a reset. This keeps large imports fast.

You can instead give them the new-account password from [Security settings](security.md#passwords). Each password is hashed during the import, which is slow for thousands of people.

## Limits

- Large files are fine: the browser sends them in chunks of 50.
- Super Admin membership can't be granted by import.
- To import from a script, use `POST /api/v1/directory/import` in the [API](api.md).
