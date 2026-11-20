# Applications

An application is anything people sign in to through FlareID — an [OIDC client](oidc.md) such as a web app or Cloudflare Access, or a [SAML app](saml.md) (service provider) such as a SaaS product. Manage them all under **Applications**: one list, one add flow, whichever protocol the app speaks.

## The applications list

**Applications → All apps** shows every registered app with its protocol, who may use it (everyone, or the groups it is restricted to) and when it was created. Select an app to open its page.

Use **Restrict to groups** on an app's page to limit it: only members of the chosen groups see the app on their My account launchpad and may sign in to it.

## Add an app

Two ways from the **Applications** page:

- **Add from catalog** — a guided template for a well-known app (Slack, Salesforce, Grafana, GitLab and more). It shows the steps for both sides of the integration, asks for the values written in braces (like `{team}` or `{host}`), then creates the FlareID record prefilled.
- **New OIDC client** or **New SAML app** — a blank record you fill in yourself. For SAML, importing the app's metadata is fastest.

## App catalog

The catalog under **Applications → App catalog** lists the templates that ship with FlareID. Each entry gives:

1. **In the app** — what to configure on the app's side.
2. **In FlareID** — what the template creates, and the values only you know (`{team}`, `{host}` and so on).

Applying a template creates the same record as the manual form — nothing is locked in afterwards; open the app and adjust anything. The generated client ID and secret appear once, when the record is created.

## Provisioning

Each app's page has a **Provisioning** card. **Set up provisioning** creates a [SCIM target](scim.md) linked to that app, so its users and groups can be pushed to the app's own provisioning endpoint. Directory-wide targets still live under **Integrations → SCIM provisioning**.
