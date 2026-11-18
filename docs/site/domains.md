# Domains

Domains are the part of a UPN after the `@`. FlareID can hold people on several domains at once, for example after an acquisition, or to keep contractors on their own domain.

## Manage domains

Go to **Domains**:

- **Add** a domain to make it available when creating users.
- **Make default** to choose the domain new users and imports get when none is given.
- **Apply to all users** moves every user onto that domain. Their usernames stay the same.
- **Delete** a domain nobody is using.

Usernames are unique across every domain, so `ada@example.com` and `ada@example.org` can't both exist.

## Brands per domain

Each domain can have its own [brand](branding.md#brands): logo, colours and emails. Choose it in the domain's **Brand** column.

## Domains and email

People's UPNs don't need to receive mail. If a UPN isn't a real mailbox, set a separate email address on the user. To send mail *from* a domain, it must be onboarded to Cloudflare Email Sending. See [Email](email.md).
