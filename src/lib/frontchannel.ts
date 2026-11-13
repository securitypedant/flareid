import type { Env } from "../env.js";
import { escapeHtml, page, scriptTag } from "./html.js";
import { DEFAULT_LOCALE, localeInfo, t as translate, tPlural, type Locale, type MessageKey } from "./i18n.js";
import { oidcSid } from "./sessions.js";

/**
 * OpenID Connect Front-Channel Logout 1.0: when an IdP session ends, every
 * client it signed the user in to that registered a frontchannel_logout_uri is
 * loaded in a hidden iframe with `iss` and `sid`, so it can end its own session.
 */

export async function frontchannelTargets(env: Env, sessionId: string): Promise<string[]> {
  const { results } = await env.DB.prepare(
    `SELECT DISTINCT oc.frontchannel_logout_uri AS uri FROM session_clients sc
       JOIN oauth_clients oc ON oc.client_id = sc.client_id
      WHERE sc.session_id = ? AND oc.frontchannel_logout_uri != ''`
  )
    .bind(sessionId)
    .all<{ uri: string }>();
  await env.DB.prepare("DELETE FROM session_clients WHERE session_id = ?").bind(sessionId).run();
  const sid = await oidcSid(sessionId);
  return results.map((r) => {
    const url = new URL(r.uri);
    url.searchParams.set("iss", env.ISSUER_URL);
    url.searchParams.set("sid", sid);
    return url.toString();
  });
}

/** Waits for every iframe (or four seconds), then continues to data-next. */
const CONTINUE_SCRIPT = `(function(){
  var box=document.getElementById("fcl"); if(!box) return;
  var next=box.getAttribute("data-next"), frames=box.querySelectorAll("iframe"), left=frames.length, done=false;
  function go(){ if(done) return; done=true; if(next) location.replace(next); else { var m=document.getElementById("fcl-done"); if(m) m.hidden=false; } }
  frames.forEach(function(f){ f.addEventListener("load", function(){ if(--left<=0) go(); }); });
  setTimeout(go, 4000);
})();`;

/** The interstitial page, in the sign-in pages' language; `frameSrc` goes into the response CSP. */
export function frontchannelLogoutPage(appName: string, targets: string[], next: string | null, locale: Locale = DEFAULT_LOCALE): { html: string; frameSrc: string } {
  const origins = [...new Set(targets.map((t) => new URL(t).origin))];
  const tx = (key: MessageKey) => escapeHtml(translate(locale, key));
  const { code, dir } = localeInfo(locale);
  const html = page(
    translate(locale, "logout.progress.title"),
    `<h1>${tx("logout.progress.heading")}</h1>
     <p class="sub" role="status">${escapeHtml(tPlural(locale, "logout.progress.apps", targets.length))}</p>
     <div id="fcl" data-next="${escapeHtml(next ?? "")}">
       ${targets.map((t) => `<iframe src="${escapeHtml(t)}" title="${tx("logout.progress.frame")}" style="display:none;" width="0" height="0"></iframe>`).join("")}
     </div>
     <p id="fcl-done" role="status" hidden>${tx("logout.progress.done")} <a href="/login">${tx("common.signInAgain")}</a></p>
     ${scriptTag(CONTINUE_SCRIPT)}`,
    appName,
    false,
    "",
    "",
    "",
    "",
    { code, dir }
  );
  return { html, frameSrc: origins.join(" ") };
}
