# Branding

Make the sign-in pages, My account and emails look like your organisation. Set a default brand for everyone, and optionally a different brand for each email domain.

## Default brand

Go to **Branding → Settings**:

| Setting | What it changes |
|---|---|
| **Logo** | Shown on the sign-in pages, in the top bar and in emails. PNG or JPEG, up to 256 KB. |
| **App name** | The name in page titles, the top bar and the sign-in page. |
| **Sign-in page message** | A line of text under the logo on the sign-in page. |
| **Login page appearance** | The background gradient behind the sign-in card. |
| **Cursor trail** | Decorative characters that follow the pointer on the sign-in page. Enter your company name to spell it out. |
| **Language** | The default language for the sign-in pages. People can still pick their own. |
| **Dates** | Pin the console to one timezone, so everyone reading the audit log sees the same times. |
| **Custom CSS** | Your own stylesheet for the sign-in pages. |

## Brands

A brand gives the people on one or more domains their own logo, app name, colours, custom CSS and email accent. Anything a brand leaves empty comes from the default brand.

1. Go to **Branding → Brands** and create a brand.
2. Set its logo, app name, message and colours.
3. Under **Domains**, choose the domains it applies to. You can also pick a brand per domain on the [Domains](domains.md) page.

### Which brand people see

- Once FlareID knows who someone is (after they enter their username, in My account, and in every email to them), they see the brand of their UPN's domain.
- On the first sign-in screen, FlareID uses the domain from the app's `login_hint`, a `?domain=example.com` link, or the hostname, if it matches a brand.

**Preview the sign-in page** on a brand's page shows how it looks, without signing out.

## Custom CSS

Custom CSS applies only to the sign-in, second-step, consent, recovery, invitation and setup pages. It never applies to the admin console or My account, so a stylesheet that breaks a page can't lock you out of fixing it.

Fonts and images must be served from your FlareID hostname or embedded in the CSS, because pages block content from other sites.

## Languages

The sign-in pages are available in English, French and German. People see the language they pick on the sign-in page, otherwise the one their browser or the app asks for, otherwise the default above.

## Email

Email wording and the accent colour are under **Branding → Email templates**. See [Email](email.md#templates).
