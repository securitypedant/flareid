# Applications

An application is anything people sign in to through FlareID — an [OIDC client](oidc.md) such as a web app or Cloudflare Access, or a [SAML app](saml.md) (service provider) such as a SaaS product. Manage them all under **Applications**: one list, one add flow, whichever protocol the app speaks.

## The applications list

**Applications → All apps** shows every registered app with its protocol, who may use it and when it was created. Search by name, filter by protocol or access mode, and pick 25, 50 or 100 rows per page. Select an app to open its page.

## The app's tabs

Each app's page is split into four tabs:

- **Settings** — endpoints, credentials and protocol options.
- **Access** — who may use the app (below).
- **Policies** — what a sign-in must satisfy to open the app (below).
- **Provisioning** — the SCIM target that pushes users and groups to the app.

## Who may use an app (Access tab)

Every app is **restricted** by default — nobody can sign in until you assign people or groups on the **Access** tab. Switch the mode to **Everyone** to open it to the whole directory. Assignments accept individual people as well as static *and* dynamic groups (dynamic membership follows the group's rule).

**Let people request access** — the app appears in the request picker under **My account → Access** for people it excludes. An approved request assigns the person directly.

## Sign-in requirements (Policies tab)

Two controls decide what a sign-in must present before it may open the app:

- **Authentication policy** — bind one of the policies defined under [Security → Policies](policies.md). The app then demands whatever that policy requires: a second-factor policy steps the session up, and device-certificate or risk conditions deny the sign-in outright. The default, *Person's own policy*, applies each sign-in's own requirement with no extra demands.
- **Require a second-factor sign-in** — the simpler option: the session must have used a second factor, whatever the person's policy would normally ask.

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

Each app's **Provisioning** tab carries its provisioning card. **Set up provisioning** creates a [SCIM target](scim.md) linked to that app, so its users and groups can be pushed to the app's own provisioning endpoint. Directory-wide targets still live under **Integrations → SCIM provisioning**.
