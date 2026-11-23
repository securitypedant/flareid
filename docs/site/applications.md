# Applications

An application is anything people sign in to through FlareID — an [OIDC client](oidc.md) such as a web app or Cloudflare Access, or a [SAML app](saml.md) (service provider) such as a SaaS product. Manage them all under **Applications**: one list, one add flow, whichever protocol the app speaks.

## The applications list

**Applications → All apps** shows every registered app with its protocol, who may use it and when it was created. Search by name, filter by protocol or access mode, and pick 25, 50 or 100 rows per page. Select an app to open its page.

## Who may use an app

Every app is **restricted** by default — nobody can sign in until you assign people or groups on the app's page. Switch the mode to **Everyone** to open it to the whole directory. Assignments accept individual people as well as static *and* dynamic groups (dynamic membership follows the group's rule).

Two more switches live on the same card:

- **Require a second-factor sign-in** — people signing in to this app must complete a second factor, whatever their authentication policy would normally ask.
- **Let people request access** — the app appears in the request picker under **My account → Access** for people it excludes. An approved request assigns the person directly.

## Add an app

Two ways from the **Applications** page:

- **Add from catalog** — a guided template for a well-known app (Slack, Salesforce, Grafana, GitLab and more). It shows the steps for both sides of the integration, asks for the values written in braces (like `{team}` or `{host}`), then creates the FlareID record prefilled.
- **New OIDC client** or **New SAML app** — a blank record you fill in yourself. For SAML, importing the app's metadata is fastest.

## App catalog

The catalog under **Applications → App catalog** lists the templates that ship with FlareID. Each entry gives:

1. **In the app** — what to configure on the app's side.
2. **In FlareID** — what the template creates, and the values only you know (`{team}`, `{host}` and so on).

Applying a template creates the same record as the manual form — nothing is locked in afterwards; open the app and adjust anything. The generated client ID and secret appear once, when the record is created. The entry's icon is set as the app's logo, so the tile shows it on the launchpad straight away.

## App icons

Every app can carry a **Logo URL** (on its page, https only) — the mark shown on its tile in users' **Applications** page, and for OIDC clients also on the sign-in page. Leave it empty for the default letter tile. Catalog apps get their icon automatically from `/catalog-icons/`.

## Provisioning

Each app's page has a **Provisioning** card. **Set up provisioning** creates a [SCIM target](scim.md) linked to that app, so its users and groups can be pushed to the app's own provisioning endpoint. Directory-wide targets still live under **Integrations → SCIM provisioning**.
