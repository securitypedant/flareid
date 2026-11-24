# Manual test script

What the automated layers can't reach. `npm test` covers services and routes
against local D1, `e2e/smoke.mjs` drives the real HTTP surface, and
`e2e/ux.spec.mjs` renders in Chromium — but none of them can touch a live
Cloudflare Zero Trust account, a real authenticator, actual mail delivery,
deployment-conditional controls (Access JWT, mTLS, risk data), or whether a
human finds the UI honest and pleasant. This script covers that ground.

Work top to bottom; each section names its prerequisites. Record failures
with the step number, what you saw, and a screenshot or HAR where relevant.

Legend: **[ZT]** needs a real Zero Trust account · **[HW]** needs hardware ·
**[LIVE]** needs the deployed instance, not `wrangler dev` · **[2P]** needs a
second person or account.

---

## 1. First-run and setup [LIVE]

1. Open the deployed instance in a **private window** — you should land on
   `/setup`, not a login page. No console errors.
2. Complete setup. Check the admin nav renders immediately (no flash of
   missing items) and the version in the nav bar matches the release.
3. Open `.well-known/openid-configuration` in a second tab — valid JSON,
   `issuer` matches the public URL.
4. Open the workers.dev hostname in a private window — if it returns Access
   error 1050, the deployment doc tells you to use the custom domain; confirm
   the custom domain answers instead.

## 2. Sign-in UX [HW]

5. Sign in with a wrong password — error renders inline, no layout jump, the
   UPN field keeps its value.
6. Sign in correctly on a phone (or narrow viewport) — the form is usable,
   buttons reachable, no horizontal scroll.
7. Register a passkey with a **real authenticator** (platform key, security
   key, or phone). Enrolment ends on the backup-codes page — codes download,
   Continue returns you where you were headed.
8. Sign out, sign in with the passkey — fresh-session indicator, no password
   asked.
9. Use a backup code at sign-in — accepted once; the same code a second time
   is refused. The remaining-codes count drops.
10. Regenerate codes from My account → Security — you are asked to step up
    (passkey or recent password), old set is invalidated.
11. Sign in on a second browser/profile — sessions coexist; signing out of
    one doesn't disturb the other.

## 3. Step-up and the admin console [LIVE]

12. As an admin, start a destructive action that needs step-up (e.g. deleting
    a signing key). The reauth card is centered; confirm it works with both
    password and passkey.
13. After reauth, the resume page shows a **spinner**, not text; the action
    completes without re-filling the form. With JS disabled, a Continue
    button appears instead.
14. Try `GET /admin` with a valid session but no step-up where required —
    you're taken through reauth, not silently allowed.

## 4. Launchpad and Access requests

15. Assign an OIDC app and a SAML SP to a user's group — both cards appear on
    their Applications page with correct badges; clicking launches the right
    flow (authorize / IdP-initiated SSO).
16. Unassign — the card disappears on next load (not after a delay you could
    mistake for caching).
17. Request access to a requestable group from a non-member account; the
    pending badge appears on **Access** in the admin nav for an approver;
    approve — the requester's launchpad/groups update and the audit log
    shows `access.request_approved`.
18. Deny a second request — requester sees the denial and note.
19. A group **manager** (not admin) tries to request the group they manage —
    told to add themselves on Manage instead.

## 5. Cloudflare One — Access applications [ZT]

20. On Integrations → Cloudflare One, connect a real account (token needs
    Zero Trust: Read at minimum — verify a read-only token suffices for the
    pull).
21. Click **Sync applications now** — real Access apps appear with name,
    type badge, hostname link, and "Policies name:" hints where the app's
    Allow policies select a group.
22. Map an app to a static group; a member's launchpad shows the card;
    clicking it lands on the Access-protected hostname.
23. Enable **Requestable** — a non-member sees it in My account → Access
    picker; approving the request joins the granting group. Check the audit
    log names the app.
24. In Zero Trust, rename an app and remove another — next sync (or Sync
    now) reflects both; pending requests for the removed app are gone.
25. Change the "Refresh every" select — saves on change; the value survives
    a page reload.
26. Disconnect the account (clear Account ID, save) — the Access
    applications card shows the unconfigured hint and the launchpad loses
    all cfapp cards.
27. **Session lag check**: approve an Access-app request for a user with an
    active Access session — they may not reach the app until their Access
    session re-auths. Verify this is the lag you expect (it's inherent to
    Access, not a FlareID bug).

## 6. Cloudflare One — the rest of the integration [ZT]

28. Enable a list sync, Sync now, and check the list exists in the ZT
    dashboard with the right items.
29. Flag a user on the watchlist — the Risk watchlist group gains them and
    the CF list (if synced) has their email.
30. Put the admin console behind an Access application, set team + AUD —
    pages only answer through Access; direct workers.dev access is refused.
    *(Have a second admin path ready before testing lockout.)*
31. With a WARP client presenting a device cert [HW], a policy requiring
    `device_cert` admits you; without the cert, sign-in is denied with the
    managed-device message.
32. If the ZT account has real risk scores, set a `max_risk` policy and
    confirm a high-risk user is denied at sign-in.

## 7. Admin console polish

33. Groups page — the "With roles" control is a switch, toggles the filter.
34. Integrations page — cards are grouped outbound → inbound → platform and
    match the nav sub-order.
35. Users page — activate/deactivate via the switch; a deactivated user is
    signed out immediately (try their session in another tab).
36. Access page — requests and reviews render, search filters, the pending
    badge count matches the table.
37. Security → Policies — a policy shows its bound apps in "Applies to";
    binding an app from its Policies tab reflects back here.
38. App edit pages — each tab saves independently: changing Settings doesn't
    clear assignments (verify on the Access tab after saving).
39. Dark/light/system theme — check the new pages (Access, CF One card,
    app tabs) in both themes for contrast and broken colors.
40. Every (?) help icon in the nav lands on a real docs anchor.

## 8. Federation and real third parties [2P, LIVE]

41. Configure a real upstream IdP (federation or a social provider) — sign
    in through it; JIT user is created with sane attributes; group claims
    land as expected.
42. SCIM-provision into the ZT account (docs/cloudflare-access.md §4) — new
    user appears in ZT, disabled user loses access promptly.
43. Point a real SAML SP at FlareID (or a SaaS like the lab's) — full
    SP-initiated login, assertion validates, attributes arrive.
44. Point a real OIDC app at FlareID — authorize, consent (if untrusted),
    token, userinfo, refresh, logout clears the RP session.

## 9. Negative and edge UX

45. Expire a session (wait out or clear cookies mid-flow) — next action
    bounces to login cleanly, and the post-login resume lands where you
    meant to go.
46. Request access, then have the target made non-requestable before
    approval — the pending request can't be approved (error, stays pending
    or is cleaned up per the rules for that target).
47. Delete a granting group with pending cfapp requests — requests are
    removed, no 500s on /admin/access.
48. Throttle your browser (devtools slow 3G) through the login flow — no
    double-submit, flow_id reuse is handled, error pages are readable.
49. Keyboard-only through: login → My account → MFA setup → request access.
    Focus is visible everywhere; switches toggle with Space.
50. Screen reader pass on the launchpad and request picker — cards are
    announced as links with app names; the spinner has an accessible label.

## 10. Operations

51. Trigger the scheduled task (wait for cron or run it manually in dev) —
    logs show `cfone_sync` including `apps` count; no `cfone_access_apps_failed`.
52. Check `wrangler tail` during a busy minute — no unhandled exceptions,
    no secrets or tokens in log lines.
53. Export the audit log and verify the hash chain after a busy session.
54. Take a backup and restore it to a scratch deployment — everything
    survives including cf_access_apps rows (mapping is data, not config).

---

## If you only have 30 minutes

Steps 6–9 (real authenticator + codes), 20–24 (ZT pull + request), 30
(Access-protected console), 45 (session resume). These four clusters are
where production surprises live.
