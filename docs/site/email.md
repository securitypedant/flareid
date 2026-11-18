# Email

FlareID sends email for invitations, password resets and sign-in codes, using Cloudflare Email Sending. Until email is set up, those features stay off and administrators set passwords by hand.

## Set up email

1. Onboard a domain you send from to Cloudflare Email Sending. From a clone of the repository:

   ```sh
   npx wrangler email sending enable example.com
   ```

2. In FlareID, go to **Integrations → Email**.
3. Enter the **From address** (on the onboarded domain, such as `no-reply@example.com`) and a **From name**, and save.
4. Select **Send a test email to me** to check it works.

Use **Switch email off** to stop all email without losing the settings.

## What email turns on

- **Forgot your password?** on the sign-in page.
- **Email them an invitation** when creating a user, and **Send reset link** on a user's page.
- **Email one-time code** as a second factor, once you turn it on under [Policies and second factors](policies.md#second-factors).

Mail goes to a person's primary email address, or to their UPN if they don't have one.

## Templates

Change the wording under **Branding → Email templates**. There are three templates:

| Template | Sent when | Placeholders |
|---|---|---|
| **Invitation** | You invite a new user. | `{{app_name}}`, `{{name}}` |
| **Password reset** | Someone asks to reset their password, or you send a reset link. | `{{app_name}}`, `{{name}}` |
| **Sign-in code** | Someone signs in with an email code. | `{{app_name}}`, `{{name}}`, `{{code}}`, `{{minutes}}` |

Each template has a subject, heading, body, button text and footer. The preview shows your changes with sample values. **Reset to default** restores the original wording.

The **Accent colour** sets the colour of buttons and links in every email. [Brands](branding.md#brands) can set their own accent colour and logo.
