import { escapeHtml, page } from "./html.js";
import type { LoginGradient } from "./settings.js";

/** Inline <style> override for the auth-flow pages (login, MFA) - a full-bleed gradient behind the centered card. */
function gradientStyles(gradient: LoginGradient): string {
  return `
    body { min-height: 100vh; background: linear-gradient(45deg, ${gradient.from}, ${gradient.to}); }
    .center-wrap { margin-top: 11vh; position: relative; }
    .center-wrap .card { padding: 32px 32px 28px; }
    .auth-brand { display: flex; align-items: center; justify-content: center; gap: 14px; margin-bottom: 10px; }
    .auth-brand img { width: 52px; height: 52px; border-radius: 12px; object-fit: contain; }
    .auth-brand span { font-size: 1.75rem; font-weight: 700; color: var(--fi-ink); letter-spacing: -0.025em; }
    .center-wrap h1 { text-align: center; font-size: 1.25rem; margin: 0 0 6px 0; }
    .center-wrap p.sub { text-align: center; margin: 0 0 24px; font-size: 0.9375rem; }
    .center-wrap form .row { margin-top: 20px; }
    .center-wrap form .row button { width: 100%; padding: 10px 16px; font-size: 0.9375rem; }
    .auth-foot { margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--fi-line); text-align: center; }
    #cursor-fx { position: fixed; inset: 0; width: 100%; height: 100%; pointer-events: none; }
  `;
}

/** The product mark above the sign-in form, as every IdP puts there. */
function authBrand(appName: string): string {
  return `<div class="auth-brand">
    <img src="/FlareID_Icon.png" alt="" onerror="this.style.display='none'" />
    <span>${escapeHtml(appName)}</span>
  </div>`;
}

/**
 * A faint field of symbols that drift away from the cursor as it moves, similar
 * to the effect on Cloudflare's AI Playground - purely decorative, GPU-cheap
 * (canvas + a handful of short-lived particles), and inert on touch devices
 * (no pointermove without a pointer).
 */
const CURSOR_FX_SCRIPT = `
(function () {
  var canvas = document.getElementById("cursor-fx");
  if (!canvas) return;
  var ctx = canvas.getContext("2d");
  var symbols = ["{ }", "0 1", "< />", "λ", "→", "*", "#", "::", "[ ]", "→→", "←←", "↑↑", "↓↓", "&", "|", "@", "%"];
  var particles = [];
  var dpr = window.devicePixelRatio || 1;

  function resize() {
    canvas.width = window.innerWidth * dpr;
    canvas.height = window.innerHeight * dpr;
    canvas.style.width = window.innerWidth + "px";
    canvas.style.height = window.innerHeight + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  resize();
  window.addEventListener("resize", resize);

  function spawn(x, y) {
    particles.push({
      x: x + (Math.random() - 0.5) * 30,
      y: y + (Math.random() - 0.5) * 30,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4 - 0.15,
      life: 0,
      maxLife: 70 + Math.random() * 40,
      size: 12 + Math.random() * 8,
      text: symbols[(Math.random() * symbols.length) | 0],
    });
    if (particles.length > 60) particles.shift();
  }

  var lastSpawn = 0;
  window.addEventListener("pointermove", function (e) {
    var now = performance.now();
    if (now - lastSpawn < 60) return;
    lastSpawn = now;
    spawn(e.clientX, e.clientY);
  });

  function tick() {
    ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
    particles = particles.filter(function (p) {
      p.life++;
      p.x += p.vx;
      p.y += p.vy;
      var t = p.life / p.maxLife;
      if (t >= 1) return false;
      var alpha = t < 0.15 ? t / 0.15 : 1 - (t - 0.15) / 0.85;
      ctx.font = p.size + "px monospace";
      ctx.fillStyle = "rgba(255, 255, 255, " + (alpha * 0.45).toFixed(3) + ")";
      ctx.fillText(p.text, p.x, p.y);
      return true;
    });
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
})();
`;

const CURSOR_FX_HTML = `<canvas id="cursor-fx"></canvas><script>${CURSOR_FX_SCRIPT}</script>`;

export function loginForm(
  appName: string,
  flowId: string,
  gradient: LoginGradient,
  subtitle: string,
  error?: string
): string {
  return page(
    "Sign in",
    `
    ${authBrand(appName)}
    ${subtitle ? `<p class="sub">${escapeHtml(subtitle)}</p>` : ""}
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <form method="POST" action="/login">
      <input type="hidden" name="flow_id" value="${escapeHtml(flowId)}" />
      <label for="upn">Username</label>
      <input type="text" id="upn" name="upn" placeholder="username or username@domain" required autofocus autocapitalize="off" autocorrect="off" />
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required />
      <div class="row"><button class="primary" type="submit">Sign in</button></div>
    </form>
    <div class="auth-foot"><span class="muted">Protected by ${escapeHtml(appName)} single sign-on</span></div>
    `,
    appName,
    false,
    "",
    gradientStyles(gradient),
    CURSOR_FX_HTML
  );
}

export function mfaForm(appName: string, mfaId: string, gradient: LoginGradient, error?: string): string {
  return page(
    "Two-factor authentication",
    `
    ${authBrand(appName)}
    <h1>Two-step verification</h1>
    <p class="sub">Enter the 6-digit code from your authenticator app, or one of your backup codes if you've lost access to it.</p>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <form method="POST" action="/login/mfa">
      <input type="hidden" name="mfa_id" value="${escapeHtml(mfaId)}" />
      <label for="code">Authenticator code or backup code</label>
      <input type="text" id="code" name="code" maxlength="12" required autofocus />
      <label style="display:flex; align-items:center; gap:6px; font-weight:400;">
        <input type="checkbox" name="remember_device" value="1" style="width:auto;" /> Remember this device for 30 days
      </label>
      <div class="row"><button class="primary" type="submit">Verify</button></div>
    </form>
    `,
    appName,
    false,
    "",
    gradientStyles(gradient),
    CURSOR_FX_HTML
  );
}
