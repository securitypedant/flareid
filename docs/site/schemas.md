# Schemas

A schema lists the attributes a user or group has beyond their name, such as job title, cost centre or office. Use schemas to keep the fields your organisation needs, and to control which fields people may edit themselves.

## How schemas work

- Every user and group uses one schema. New ones get the **default** schema.
- FlareID ships a **FlareID HR** schema covering job title, department, manager, employee number, hire date, employment status and type, and location.
- Moving someone to another schema keeps the attributes with the same name and clears the rest.

## Create a schema

1. Go to **Schemas → New schema**.
2. Choose the object type (**User** or **Group**), and give it a name and description.
3. Add attributes. For each one, set:
   - a **name** (used in tokens, rules and the API) and a **label** (shown in forms)
   - a **type**: text, number, date, yes/no, or a reference to another person (such as a manager)
   - whether it's **required**
   - whether people can **edit it themselves** in My account

## Apply to everyone

**Apply to all users** (or groups) on a schema's page moves everyone onto it. Use it after creating a new default.

## Where attributes are used

- [Dynamic group](groups.md#static-and-dynamic-groups) rules.
- OIDC tokens: built-in HR fields are top-level claims; your own attributes are in the `custom` claim. See [OIDC clients](oidc.md#claims).
- SAML attribute maps and [SCIM](scim.md) mappings.
