import { escapeHtml, page, scriptTag } from "../html.js";

/**
 * The same auto-submitting pattern for an OAuth/OIDC `form_post` response
 * mode: the parameters that would have ridden the redirect query go as hidden
 * POST fields instead.
 */
export function formPostPage(appName: string, action: string, fields: Record<string, string>): string {
  return page(
    "Redirecting",
    `
    <p class="sub">Taking you back&hellip;</p>
    <form method="POST" action="${escapeHtml(action)}">
      ${Object.entries(fields).map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}" />`).join("\n      ")}
      <noscript><div class="row"><button class="primary" type="submit">Continue</button></div></noscript>
    </form>
    ${scriptTag("document.forms[0].submit();")}
    `,
    appName,
    false
  );
}

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
    ${scriptTag("document.forms[0].submit();")}
    `,
    appName,
    false
  );
}
