import { escapeHtml, page } from "../html.js";

/**
 * The auto-submitting form that delivers a SAML Response to a service
 * provider's ACS over the HTTP-POST binding: base64 in a hidden field, POSTed
 * by script, with a button for browsers that won't run it.
 */
export function samlPostForm(appName: string, acsUrl: string, samlResponse: string, relayState: string | null): string {
  return page(
    "Redirecting",
    `
    <p class="sub">Signing you in&hellip;</p>
    <form method="POST" action="${escapeHtml(acsUrl)}">
      <input type="hidden" name="SAMLResponse" value="${escapeHtml(samlResponse)}" />
      ${relayState !== null ? `<input type="hidden" name="RelayState" value="${escapeHtml(relayState)}" />` : ""}
      <noscript><div class="row"><button class="primary" type="submit">Continue</button></div></noscript>
    </form>
    <script>document.forms[0].submit();</script>
    `,
    appName,
    false
  );
}
