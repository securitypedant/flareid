import { VERSION } from "../version.js";

export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

const STYLES = `
  /* FlareID console.

     Deliberately restrained: an identity provider is infrastructure, and the
     visual language people expect from one is dense, neutral and quiet, with
     colour reserved for state. Cloudflare orange is the accent only - it
     marks the active thing and the primary action, never decoration.

     Every class here is used by the server-rendered pages in src/routes; the
     names are the contract, so this file changes look and not structure. */

  :root {
    --fi-accent: #f6821f;
    --fi-accent-dark: #d96d10;
    --fi-accent-soft: #fff4e9;
    --fi-ink: #0f172a;
    --fi-body: #334155;
    --fi-muted: #64748b;
    --fi-line: #e2e8f0;
    --fi-line-soft: #eef2f6;
    --fi-canvas: #f7f8fa;
    --fi-surface: #ffffff;
    --fi-green: #15803d;
    --fi-green-soft: #f0fdf4;
    --fi-red: #b91c1c;
    --fi-red-soft: #fef2f2;
    /* A chart line has to read against the orange accent at 2px: --fi-red alone
       is too close in hue, so charted failures get their own rose. */
    --fi-err-line: #e11d48;
    --fi-amber: #92400e;
    --fi-amber-soft: #fffbeb;
    --fi-radius: 10px;
    --fi-line-strong: #cbd5e1;
    --fi-faint: #94a3b8;
    --fi-surface-2: #fbfcfd;
    color-scheme: light;
  }

  /* Dark theme: the system preference unless the user picked one (theme toggle,
     stored per browser). Only the palette changes; structure is shared. */
  :root[data-theme="dark"] {
    --fi-accent-soft: #3a2614;
    --fi-ink: #e8edf4;
    --fi-body: #c3ccd8;
    --fi-muted: #8b97a8;
    --fi-line: #2a3342;
    --fi-line-soft: #222a37;
    --fi-canvas: #0f141c;
    --fi-surface: #171d27;
    --fi-surface-2: #1b2230;
    --fi-line-strong: #3a4558;
    --fi-faint: #6b7889;
    --fi-green: #4ade80;
    --fi-green-soft: #12291c;
    --fi-red: #f87171;
    --fi-red-soft: #2c1517;
    --fi-err-line: #fb7185;
    --fi-amber: #fbbf24;
    --fi-amber-soft: #2a2110;
    color-scheme: dark;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --fi-accent-soft: #3a2614; --fi-ink: #e8edf4; --fi-body: #c3ccd8; --fi-muted: #8b97a8;
      --fi-line: #2a3342; --fi-line-soft: #222a37; --fi-canvas: #0f141c; --fi-surface: #171d27;
      --fi-surface-2: #1b2230; --fi-line-strong: #3a4558; --fi-faint: #6b7889; --fi-green: #4ade80;
      --fi-green-soft: #12291c; --fi-red: #f87171; --fi-red-soft: #2c1517; --fi-err-line: #fb7185; --fi-amber: #fbbf24;
      --fi-amber-soft: #2a2110; color-scheme: dark;
    }
  }
  input, select, textarea { background-color: var(--fi-surface); color: var(--fi-ink); }
  .theme-toggle { background: none; border: 1px solid var(--fi-line); border-radius: 6px; color: var(--fi-muted); cursor: pointer; font-size: 0.8125rem; padding: 4px 8px; display: inline-flex; align-items: center; }
  .theme-toggle svg { width: 14px; height: 14px; }
  .theme-toggle:hover { color: var(--fi-ink); background: var(--fi-line-soft); }
  .brand-version { color: var(--fi-faint); font-weight: 500; margin-left: 4px; }
  .topbar .brand-row { display: flex; align-items: center; gap: 6px; }
  .topbar a.github-link { display: inline-flex; align-items: center; padding: 6px; border-radius: 6px; color: var(--fi-muted); }
  .topbar a.github-link:hover { color: var(--fi-ink); background: var(--fi-line-soft); text-decoration: none; }

  /* List toolbars: filters left, actions right, one row while it fits. */
  .list-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin: 0; }
  .list-toolbar-filters, .list-toolbar-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .list-toolbar input[type=text], .list-toolbar input[type=search] { width: 260px; margin: 0; }
  .list-toolbar select, .list-toolbar .searchselect { width: auto; margin: 0; }
  .list-toolbar-actions a { display: inline-flex; }

  .auth-passkey { margin-top: 12px; }

  /* Narrow centered card (step-up, confirmations) */
  .center-narrow { max-width: 460px; margin: 6vh auto 0; }
  .center-narrow .card { padding: 26px 28px 22px; }
  .center-narrow h2 { margin: 0 0 6px; }
  .spin-wrap { display: flex; justify-content: center; padding: 40px 0; }
  .spinner { width: 36px; height: 36px; border-radius: 50%; border: 3px solid var(--fi-line); border-top-color: var(--fi-accent); animation: fi-spin 0.8s linear infinite; }
  @keyframes fi-spin { to { transform: rotate(360deg); } }

  /* "Use these values" panels (OIDC client and SAML SP pages) */
  .info-panel { background: var(--fi-surface-2); border: 1px solid var(--fi-line); border-radius: var(--fi-radius); padding: 14px 16px; margin: 12px 0 18px; }
  .info-panel > p.muted { margin: 0 0 10px; }
  .info-panel table { margin: 0; }
  .info-panel th { width: 170px; background: transparent; color: var(--fi-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; font-weight: 600; white-space: nowrap; vertical-align: middle; }
  .info-panel td { vertical-align: middle; }
  .info-panel tr:last-child th, .info-panel tr:last-child td { border-bottom: none; }
  .copy-value { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .copy-value code { overflow-wrap: anywhere; background: var(--fi-line-soft); color: var(--fi-ink); padding: 3px 8px; border-radius: 6px; }

  .section-title { font-size: 1.0625rem; margin: 28px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--fi-line); }

  .chart .line { stroke-width: 2; }
  .chart .dot { stroke: none; }
  .chart .line.s-p50 { stroke: var(--fi-accent); }
  .chart .dot.s-p50 { fill: var(--fi-accent); }
  .chart .line.s-p95 { stroke: var(--fi-faint); }
  .chart .dot.s-p95 { fill: var(--fi-faint); }
  .chart .line.s-err { stroke: var(--fi-err-line); stroke-width: 2.5; }
  .chart .dot.s-err, .chart text.s-err { fill: var(--fi-err-line); }
  .chart .line-halo { stroke: var(--fi-surface); stroke-width: 5.5; }
  .chart .dot-halo { stroke: var(--fi-surface); stroke-width: 1.5px; }
  .chart .bar.err { fill: var(--fi-red); }
  .range-tabs { display: inline-flex; border: 1px solid var(--fi-line); border-radius: 8px; overflow: hidden; }
  .range-tabs a { padding: 6px 12px; font-size: 0.8125rem; color: var(--fi-body); text-decoration: none; }
  .range-tabs a.active { background: var(--fi-accent-soft); color: var(--fi-accent); font-weight: 600; }

  /* CSV import */
  .import-layout { display: grid; grid-template-columns: minmax(0, 3fr) minmax(0, 2fr); gap: 18px; align-items: start; }
  @media (max-width: 980px) { .import-layout { grid-template-columns: 1fr; } }
  .drop-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  @media (max-width: 760px) { .drop-grid { grid-template-columns: 1fr; } }
  .drop-zone {
    display: flex; flex-direction: column; gap: 4px; padding: 16px; margin: 0;
    border: 1.5px dashed var(--fi-line-strong); border-radius: var(--fi-radius); background: var(--fi-surface-2); cursor: pointer;
  }
  .drop-zone:hover, .drop-zone:focus-within { border-color: var(--fi-accent); }
  .drop-zone .drop-title { font-weight: 650; color: var(--fi-ink); }
  .drop-zone input[type=file] { margin: 8px 0 4px; font-size: 0.8125rem; }
  .drop-zone .drop-hint { font-size: 0.8125rem; color: var(--fi-muted); font-weight: 400; }
  .choice { display: flex; gap: 10px; align-items: flex-start; font-weight: 400; padding: 10px 12px; border: 1px solid var(--fi-line); border-radius: 8px; margin-bottom: 8px; cursor: pointer; }
  .choice input { width: auto; margin: 3px 0 0; }
  .choice:has(input:checked) { border-color: var(--fi-accent); background: var(--fi-accent-soft); }
  .import-progress { width: 100%; height: 8px; accent-color: var(--fi-accent); }
  .import-log { max-height: 360px; min-height: 120px; overflow: auto; background: var(--fi-surface-2); border: 1px solid var(--fi-line); border-radius: 8px; padding: 10px; font-size: 0.8125rem; white-space: pre-wrap; color: var(--fi-body); }

  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: var(--fi-canvas); margin: 0; color: var(--fi-body);
    font-size: 14px; line-height: 1.55;
    -webkit-font-smoothing: antialiased;
  }
  a { color: var(--fi-accent); text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* ------------------------------------------------------------ topbar */
  .topbar {
    background: var(--fi-surface); border-bottom: 1px solid var(--fi-line);
    padding: 0 24px; height: 56px; display: flex; align-items: center; justify-content: space-between;
    position: sticky; top: 0; z-index: 10;
  }
  .topbar .brand { display: flex; align-items: center; gap: 10px; text-decoration: none; color: inherit; }
  .topbar .brand:hover { text-decoration: none; }
  .brand-logo { width: 26px; height: 26px; border-radius: 6px; object-fit: contain; flex-shrink: 0; }
  .brand-logo-custom { width: auto; max-width: 120px; border-radius: 0; }
  .topbar .brand-name { font-weight: 700; font-size: 1.0625rem; color: var(--fi-ink); letter-spacing: -0.015em; }
  .topbar .brand-tagline {
    font-size: 0.6875rem; color: var(--fi-muted); font-weight: 500;
    padding-left: 10px; margin-left: 4px; border-left: 1px solid var(--fi-line);
  }
  .topbar nav { display: flex; align-items: center; gap: 4px; }
  .topbar nav a, .topbar nav .link-button {
    color: var(--fi-body); text-decoration: none; font-size: 0.875rem; font-weight: 500;
    padding: 6px 12px; border-radius: 6px; border-bottom: none;
  }
  .topbar nav a:hover, .topbar nav .link-button:hover { background: var(--fi-line-soft); color: var(--fi-ink); text-decoration: none; }
  .topbar nav a.signout, .topbar nav .link-button.signout { color: var(--fi-muted); }
  .topbar nav a.signout:hover, .topbar nav .link-button.signout:hover { color: var(--fi-red); background: var(--fi-red-soft); }
  /* The Admin entry is a button, not a nav link: a deliberate visual break
     between the self-service pages and the console. */
  .topbar nav a.nav-admin { background: var(--fi-accent); color: #ffffff; font-weight: 600; }
  .topbar nav a.nav-admin:hover { background: var(--fi-accent-dark); color: #ffffff; }
  /* Burger menu on narrow screens: the inline links collapse into it.
     .nav-links is display:contents so the desktop flex row is unchanged. */
  .topbar nav .nav-links { display: contents; }
  .topbar nav .nav-burger { display: none; }
  .topbar nav .nav-burger .nav-menu-list { min-width: 200px; }
  /* Admin stays a button inside the burger too, not a plain menu row. */
  .nav-menu-list a.nav-admin { background: var(--fi-accent); color: #ffffff; font-weight: 600; text-align: center; }
  .nav-menu-list a.nav-admin:hover { background: var(--fi-accent-dark); color: #ffffff; }
  @media (max-width: 760px) {
    /* One menu on mobile: nav links + Admin + Theme + Sign out all live in
       the burger; the avatar dropdown, inline links and GitHub link hide. */
    .topbar nav .nav-links, .topbar nav .nav-user, .topbar a.github-link { display: none; }
    .topbar nav .nav-burger { display: inline-block; }
  }
  /* Tablet widths: the top bar is crowded even before the burger takes over,
     so the tagline (version chip) hides first. */
  @media (max-width: 980px) {
    .topbar .brand-tagline { display: none; }
  }
  @media (max-width: 640px) {
    .stat-grid { flex-wrap: wrap; }
    .stat-grid .stat-card { flex: 1 1 40%; }
    .card table { display: block; overflow-x: auto; -webkit-overflow-scrolling: touch; }
  }

  /* top-bar dropdown menus: the account menu and the notifications bell */
  .nav-menu { position: relative; display: inline-block; }
  .nav-menu-btn {
    background: none; border: none; cursor: pointer; font: inherit;
    color: var(--fi-body); font-size: 0.875rem; font-weight: 500;
    padding: 6px 12px; border-radius: 6px; display: inline-flex; align-items: center; gap: 4px;
  }
  .nav-menu-btn:hover { background: var(--fi-line-soft); color: var(--fi-ink); }
  .nav-menu.open .nav-menu-btn { background: var(--fi-line-soft); color: var(--fi-ink); }
  .nav-menu-list {
    display: none; position: absolute; right: 0; top: calc(100% + 6px); z-index: 60;
    min-width: 220px; max-width: 340px; background: var(--fi-surface);
    border: 1px solid var(--fi-line); border-radius: 10px;
    box-shadow: 0 8px 30px rgba(0,0,0,0.18); padding: 6px;
  }
  .nav-menu.open .nav-menu-list { display: block; }
  .nav-menu-list a, .nav-menu-list button.nav-item {
    display: block; width: 100%; text-align: left; padding: 8px 10px; border-radius: 6px; border: none;
    background: none; cursor: pointer; font: inherit;
    color: var(--fi-ink); font-size: 0.875rem; font-weight: 500;
  }
  .nav-menu-list a:hover, .nav-menu-list button.nav-item:hover { background: var(--fi-line-soft); text-decoration: none; }
  .nav-menu-list button.nav-item.signout:hover { color: var(--fi-red); background: var(--fi-red-soft); }
  .nav-menu-divider { border: none; border-top: 1px solid var(--fi-line); margin: 4px 0; }
  .nav-menu-name { max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }
  .notif-btn { position: relative; padding: 6px 10px !important; }
  .notif-dot {
    position: absolute; top: -4px; right: -4px; min-width: 16px; height: 16px;
    border-radius: 999px; background: var(--fi-amber); color: #1c1007;
    font-size: 0.625rem; font-weight: 700; line-height: 16px; text-align: center; padding: 0 4px;
  }
  .notif-item { display: block; padding: 8px 10px; border-radius: 6px; border-bottom: none; color: var(--fi-ink); font-size: 0.8125rem; }
  .notif-item:hover { background: var(--fi-line-soft); text-decoration: none; }
  .notif-item .notif-when { display: block; color: var(--fi-muted); font-size: 0.72rem; margin-top: 2px; }
  .notif-empty { padding: 12px 10px; color: var(--fi-muted); font-size: 0.8125rem; }
  .nav-badge {
    display: inline-block; min-width: 18px; height: 18px; border-radius: 999px;
    background: var(--fi-amber); color: #1c1007; font-size: 0.6875rem; font-weight: 700;
    line-height: 18px; text-align: center; padding: 0 5px; margin-left: 6px; vertical-align: 1px;
  }

  /* -------------------------------------------------------------- page */
  .page-wrap { max-width: 1180px; margin: 0 auto; padding: 28px 24px 40px; }
  .center-wrap { max-width: 400px; margin: 9vh auto; padding: 0 20px; }

  .card {
    background: var(--fi-surface); border: 1px solid var(--fi-line); border-radius: var(--fi-radius);
    padding: 22px 24px; margin-bottom: 18px;
  }
  .center-wrap .card { padding: 28px; box-shadow: 0 10px 34px rgba(15, 23, 42, 0.12); border-color: transparent; }

  h1 { font-size: 1.375rem; margin: 0 0 4px 0; font-weight: 650; color: var(--fi-ink); letter-spacing: -0.015em; }
  h2 { font-size: 0.9375rem; margin: 0 0 12px 0; font-weight: 650; color: var(--fi-ink); }
  h3 { font-size: 0.875rem; margin: 0 0 8px 0; font-weight: 650; color: var(--fi-ink); }
  p.sub { color: var(--fi-muted); font-size: 0.875rem; margin-top: 0; }
  .page-header { margin-bottom: 20px; }
  .page-header-row { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; flex-wrap: wrap; }

  /* Two-column attribute grid on the user/group forms */
  /* Card title on the left, a compact labelled control (e.g. Schema) on the right. */
  .card-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 18px; }
  .card-head h2, .card-head h3 { margin: 0; }
  .card-head .inline-field { display: flex; align-items: center; gap: 10px; }
  .card-head .inline-field label { margin: 0; color: var(--fi-muted); font-weight: 500; }
  .card-head .inline-field select { margin: 0; width: 220px; }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr; column-gap: 20px; row-gap: 4px; }
  .form-grid > div { min-width: 0; }
  @media (max-width: 760px) { .form-grid { grid-template-columns: 1fr; } }

  /* Labelled setting rows (user Security card) */
  .sec-row { display: flex; justify-content: space-between; align-items: center; gap: 24px; padding: 14px 0; border-top: 1px solid var(--fi-line-soft); }
  .sec-row > div:first-child { flex: 1; min-width: 0; }
  .sec-row > form, .sec-row > div:last-child:not(:first-child) { flex-shrink: 0; }
  @media (max-width: 760px) { .sec-row { flex-direction: column; align-items: stretch; gap: 10px; } .sec-row > form { justify-content: flex-end; } }
  .sec-row:first-of-type { border-top: none; padding-top: 4px; }
  .sec-row h3 { margin: 0 0 2px 0; }
  .sec-row p { margin: 0; }
  .sec-row form { margin: 0; display: flex; gap: 8px; align-items: center; }

  .notice-warn { background: #fffbeb; border: 1px solid #fde68a; color: #92400e; border-radius: 8px; padding: 10px 14px; margin-bottom: 14px; font-size: 0.875rem; }
  .rule-row { display: grid; grid-template-columns: 1.1fr 1.5fr 70px 1.4fr 44px; gap: 8px; align-items: start; margin-bottom: 8px; }
  .rule-row > * { min-width: 0; }
  .rule-row input, .rule-row select { margin-bottom: 0; }
  .rule-row.rule-expr { grid-template-columns: 70px 1fr 44px; }
  .rule-row.rule-expr .rule-schema, .rule-row.rule-expr .rule-attr { display: none; }
  .attr-row { display: grid; grid-template-columns: 1.2fr 1.4fr 1fr 100px 130px 44px; gap: 8px; align-items: center; margin-bottom: 8px; }
  .attr-row input, .attr-row select { margin-bottom: 0; }
  .attr-row label { margin: 0; font-weight: 400; display: flex; align-items: center; gap: 6px; white-space: nowrap; }
  .email-row { display: grid; grid-template-columns: 1.6fr 110px 90px 44px; gap: 8px; align-items: center; margin-bottom: 8px; }
  .email-row input, .email-row select { margin-bottom: 0; }
  .email-row label { margin: 0; font-weight: 400; display: flex; align-items: center; gap: 6px; white-space: nowrap; }
  .header-meta { font-size: 0.875rem; font-weight: 400; color: var(--fi-muted); margin-left: 10px; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-bottom: 18px; }
  /* Equal-height pairs - direct children only. A column that wraps several
     cards keeps them at natural height (the brands edit page does this). */
  .two-col > .card { margin-bottom: 0; height: 100%; }
  .two-col > div:not(.card) { display: flex; flex-direction: column; }
  .two-col > div:not(.card) > .card:last-child { margin-bottom: 0; }
  @media (max-width: 860px) { .two-col { grid-template-columns: 1fr; } }
  .three-col { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 18px; margin-bottom: 18px; }
  .three-col > .card { margin-bottom: 0; height: 100%; }
  @media (max-width: 1100px) { .three-col { grid-template-columns: 1fr 1fr; } }
  @media (max-width: 700px) { .three-col { grid-template-columns: 1fr; } }

  .breadcrumbs { font-size: 0.8125rem; color: var(--fi-muted); margin-bottom: 6px; }
  .breadcrumbs a { color: var(--fi-muted); text-decoration: none; }
  .breadcrumbs a:hover { color: var(--fi-accent); text-decoration: underline; }
  .breadcrumbs span:last-child { color: var(--fi-body); font-weight: 500; }
  .breadcrumb-sep { color: var(--fi-line-strong); margin: 0 4px; }

  /* ------------------------------------------------------------- forms */
  label { display: block; font-size: 0.8125rem; font-weight: 600; margin-bottom: 5px; color: var(--fi-ink); }
  input[type=text], input[type=search], input[type=email], input[type=url], input[type=tel], input[type=password], input[type=number], input[type=date], select, textarea {
    width: 100%; padding: 9px 12px; border: 1px solid var(--fi-line-strong); border-radius: 8px; font-size: 0.875rem;
    box-sizing: border-box; margin-bottom: 16px; font-family: inherit; color: var(--fi-ink); background: var(--fi-surface);
    transition: border-color 0.12s, box-shadow 0.12s;
  }
  input::placeholder, textarea::placeholder { color: var(--fi-faint); }
  input:focus, select:focus, textarea:focus {
    outline: none; border-color: var(--fi-accent); box-shadow: 0 0 0 3px rgba(246, 130, 31, 0.18);
  }
  /* One height for every single-line control, so date pickers and selects line up with text inputs in a grid. */
  input[type=text], input[type=search], input[type=email], input[type=url], input[type=tel], input[type=password], input[type=number], input[type=date], select { height: 38px; }
  input[type=date] { padding-right: 8px; }
  input[type=date]::-webkit-calendar-picker-indicator {
    cursor: pointer; padding: 5px; margin-left: 6px; border-radius: 6px; opacity: 0.5;
  }
  input[type=date]::-webkit-calendar-picker-indicator:hover { opacity: 1; background: var(--fi-line-soft); }
  select {
    padding-right: 32px; appearance: none; -webkit-appearance: none; -moz-appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%2364748b' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
    background-repeat: no-repeat; background-position: right 12px center;
  }
  .field-row { display: flex; gap: 12px; }
  .field-row > * { flex: 1; }
  /* Field pairs stack on small screens rather than squeezing side by side. */
  @media (max-width: 640px) { .field-row { flex-direction: column; gap: 0; } }

  button {
    padding: 8px 15px; border-radius: 8px; border: 1px solid transparent; font-size: 0.875rem;
    cursor: pointer; font-weight: 550; font-family: inherit; transition: background 0.12s, border-color 0.12s;
  }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .primary { background: var(--fi-accent); color: #fff; }
  /* A text input with its submit button beside it: flush on one 38px line, stacked on narrow screens. */
  .inline-action { display: flex; gap: 8px; align-items: center; }
  .inline-action input { flex: 1; min-width: 0; margin: 0; }
  .inline-action button { height: 38px; white-space: nowrap; flex-shrink: 0; }
  @media (max-width: 480px) { .inline-action { flex-direction: column; align-items: stretch; } }
  /* Per-row actions in a list (code entry, resend, remove): right-aligned on one line, wrapping on narrow screens. */
  .alias-actions { display: flex; gap: 12px; align-items: center; justify-content: flex-end; flex-wrap: wrap; }
  .alias-actions form { margin: 0; }
  .alias-actions .inline-action { flex-direction: row; }
  .alias-actions .inline-action input { width: 130px; flex: none; }
  .primary:hover:not(:disabled) { background: var(--fi-accent-dark); }
  .secondary { background: var(--fi-surface); color: var(--fi-body); border-color: var(--fi-line-strong); }
  .secondary:hover:not(:disabled) { background: var(--fi-line-soft); border-color: var(--fi-faint); }
  .danger { background: var(--fi-surface); color: var(--fi-red); border-color: #fecaca; }
  .danger:hover:not(:disabled) { background: var(--fi-red-soft); border-color: #f87171; }

  .error {
    color: var(--fi-red); font-size: 0.875rem; margin-bottom: 14px;
    background: var(--fi-red-soft); border: 1px solid #fecaca; border-radius: 8px; padding: 9px 12px;
  }
  .success { color: var(--fi-green); font-size: 0.875rem; margin-bottom: 12px; }
  .muted { color: var(--fi-muted); font-size: 0.8125rem; }
  .row { display: flex; justify-content: flex-end; margin-top: 8px; gap: 8px; }
  .row.between { justify-content: space-between; align-items: center; }

  /* ------------------------------------------------------------ tables */
  table { width: 100%; border-collapse: collapse; margin-top: 4px; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--fi-line-soft); font-size: 0.875rem; }
  th {
    color: var(--fi-muted); text-transform: uppercase; font-size: 0.6875rem; letter-spacing: 0.05em;
    font-weight: 650; background: var(--fi-surface-2); border-bottom-color: var(--fi-line);
  }
  tbody tr:hover { background: var(--fi-surface-2); }
  tr:last-child td { border-bottom: none; }

  /* ------------------------------------------------------------- state */
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.6875rem;
    font-weight: 650; letter-spacing: 0.01em; border: 1px solid transparent;
  }
  .badge-active { background: var(--fi-green-soft); color: var(--fi-green); border-color: #bbf7d0; }
  .badge-disabled { background: var(--fi-red-soft); color: var(--fi-red); border-color: #fecaca; }
  .badge-revoked { background: var(--fi-red-soft); color: var(--fi-red); border-color: #fecaca; }
  .badge-pending { background: var(--fi-accent-soft); color: var(--fi-amber); border-color: #fed7aa; }
  /* Status pills in a column: one width, so a column of them lines up. */
  .badge-status { min-width: 84px; text-align: center; box-sizing: border-box; }
  .badge-admin { background: var(--fi-accent-soft); color: var(--fi-amber); border-color: #fed7aa; }
  .pill {
    display: inline-block; background: var(--fi-line-soft); color: var(--fi-body); border: 1px solid var(--fi-line);
    border-radius: 6px; padding: 2px 8px; font-size: 0.75rem; margin: 0 4px 4px 0;
  }

  .link-button {
    background: none; border: none; color: var(--fi-accent); cursor: pointer; padding: 0;
    text-decoration: underline; font-size: inherit; font-weight: 400; font-family: inherit;
  }
  code {
    background: var(--fi-line-soft); border: 1px solid var(--fi-line); padding: 1px 6px; border-radius: 5px;
    font-size: 0.8125em; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--fi-ink);
  }

  /* -------------------------------------------------------------- stats */
  .stat-grid { display: flex; gap: 16px; }
  .stat-card { flex: 1; text-decoration: none; color: inherit; }
  a.stat-card:hover { text-decoration: none; }
  .stat-card .card { text-align: left; transition: border-color 0.12s, box-shadow 0.12s; }
  a.stat-card:hover .card { border-color: var(--fi-accent); box-shadow: 0 2px 10px rgba(246, 130, 31, 0.14); }
  .stat-card h2 { font-size: 2rem; margin: 0; color: var(--fi-ink); font-weight: 300; letter-spacing: -0.02em; }
  .stat-card p {
    margin: 2px 0 0 0; color: var(--fi-muted); font-size: 0.6875rem;
    text-transform: uppercase; letter-spacing: 0.05em; font-weight: 650;
  }

  /* --------------------------------------------------------- section nav */
  /* The admin shell spans the window with the topbar's 24px gutter, so the menu
     sits directly under the logo at every width instead of floating inside a
     centred column. The content column uses the rest of the window. */
  .page-wrap:has(> .admin-shell) { max-width: none; padding-left: 24px; padding-right: 24px; }
  .admin-shell { display: grid; grid-template-columns: 196px minmax(0, 1fr); gap: 36px; align-items: start; }
  .admin-main { min-width: 0; }
  /* Pull the menu left by its link padding so the label text lines up with the logo. */
  .admin-side { position: sticky; top: 80px; display: flex; flex-direction: column; gap: 2px; margin-left: -14px; }
  .admin-side a {
    padding: 8px 12px; text-decoration: none; font-size: 0.875rem; font-weight: 550;
    color: var(--fi-muted); border-radius: 8px; border-left: 2px solid transparent;
  }
  .admin-side a:hover { background: var(--fi-line-soft); color: var(--fi-ink); text-decoration: none; }
  .admin-side a.active { background: var(--fi-accent-soft); color: var(--fi-accent); border-left-color: var(--fi-accent); }
  /* Log page filter bar */
  .log-filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .log-filters input[type="text"] { flex: 1 1 240px; max-width: 320px; }
  .log-date { display: inline-flex; align-items: center; gap: 6px; margin: 0; font-weight: 500; font-size: 0.8125rem; color: var(--fi-muted); }
  .log-date input { width: auto; }
  /* A section's own pages (Integrations), indented under it. */
  .admin-side a.sub { padding: 5px 12px 5px 26px; font-size: 0.8125rem; font-weight: 500; }
  .admin-side a.sub.active { background: transparent; color: var(--fi-accent); border-left-color: var(--fi-accent); }
  .admin-main { min-width: 0; }
  /* The Docs link closing the console menu, and the (?) beside page titles. */
  .admin-side a.nav-docs { margin-top: 10px; padding-top: 12px; border-top: 1px solid var(--fi-line); border-radius: 0 0 8px 8px; display: flex; align-items: center; gap: 6px; }
  .admin-side a.nav-docs svg { opacity: 0.7; }
  .page-title { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .help-link {
    display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0; width: 20px; height: 20px; margin-bottom: 4px;
    border-radius: 999px; border: 1.5px solid var(--fi-line-strong); color: var(--fi-muted);
    font-size: 0.75rem; font-weight: 700; line-height: 1; text-decoration: none;
  }
  .help-link:hover { border-color: var(--fi-accent); color: var(--fi-accent); background: var(--fi-accent-soft); text-decoration: none; }
  /* On mobile the sidebar collapses into a disclosure: a tappable section
     name that opens the same links vertically. The inline sidebar is
     desktop-only. */
  .admin-nav-mobile { display: none; }
  @media (max-width: 900px) {
    .admin-shell { grid-template-columns: 1fr; }
    .admin-side-desktop { display: none; }
    .admin-nav-mobile { display: block; margin-bottom: 18px; border: 1px solid var(--fi-line); border-radius: var(--fi-radius); background: var(--fi-surface); }
    .admin-nav-mobile summary { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 11px 14px; font-weight: 600; font-size: 0.9rem; color: var(--fi-ink); cursor: pointer; list-style: none; }
    .admin-nav-mobile summary::-webkit-details-marker { display: none; }
    .admin-nav-mobile summary svg { color: var(--fi-muted); transition: transform 0.15s; flex-shrink: 0; }
    .admin-nav-mobile[open] summary svg { transform: rotate(180deg); }
    .admin-nav-mobile .admin-side { position: static; margin-left: 0; padding: 4px 8px 10px; border-top: 1px solid var(--fi-line); }
    .admin-nav-mobile .admin-side a { display: block; padding: 8px 12px; }
    .admin-nav-mobile .admin-side a.sub { padding: 6px 12px 6px 28px; }
    .admin-nav-mobile .admin-side a.nav-docs { margin-top: 8px; padding-top: 10px; border-top: 1px solid var(--fi-line); border-radius: 0; }
  }

  /* Row overflow menu (users/groups lists) */
  .rowmenu { position: relative; display: inline-block; }
  .rowmenu > button { background: none; border: none; cursor: pointer; font-size: 1.1rem; padding: 0 8px; color: var(--fi-muted); line-height: 1; }
  .rowmenu > button:hover { color: var(--fi-ink); }
  .rowmenu-items {
    display: none; position: absolute; right: 0; top: 100%; z-index: 30; min-width: 120px;
    background: var(--fi-surface); border: 1px solid var(--fi-line); border-radius: 8px; box-shadow: 0 4px 16px rgba(0,0,0,0.1); padding: 4px;
  }
  .rowmenu.open .rowmenu-items { display: block; }
  .rowmenu-items a, .rowmenu-items button {
    display: block; width: 100%; text-align: left; padding: 7px 10px; font-size: 0.8125rem;
    background: none; border: none; border-radius: 5px; color: var(--fi-ink); text-decoration: none; cursor: pointer;
  }
  .rowmenu-items a:hover, .rowmenu-items button:hover { background: var(--fi-line-soft); }
  .rowmenu-items button.danger { color: #b91c1c; }

  /* Toggle switch (account status etc.) */
  .switch { position: relative; display: inline-flex; align-items: center; gap: 8px; cursor: pointer; }
  .switch input { position: absolute; opacity: 0; width: 0; height: 0; }
  .switch .track {
    width: 38px; height: 22px; border-radius: 11px; background: var(--fi-line); transition: background 0.15s;
    position: relative; flex-shrink: 0;
  }
  .switch .track::after {
    content: ""; position: absolute; top: 3px; left: 3px; width: 16px; height: 16px; border-radius: 50%;
    background: var(--fi-surface); box-shadow: 0 1px 3px rgba(0,0,0,0.3); transition: left 0.15s;
  }
  .switch input:checked + .track { background: var(--fi-accent); }
  .switch input:checked + .track::after { left: 19px; }

  /* Searchable single-select (manager picker, rule builder) */
  .searchselect { position: relative; margin-bottom: 16px; }
  .rule-row .searchselect { margin-bottom: 0; }
  /* Styled to match a native <select> exactly - same border, height and chevron. */
  .searchselect .ss-toggle {
    width: 100%; height: 38px; text-align: left; display: flex; align-items: center;
    padding: 0 32px 0 12px; border: 1px solid var(--fi-line-strong); border-radius: 8px; color: var(--fi-ink);
    font-size: 0.875rem; font-weight: 400; box-shadow: none; cursor: pointer;
    background: var(--fi-surface) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%2364748b' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") no-repeat right 12px center;
  }
  .searchselect .ss-toggle:hover { border-color: var(--fi-faint); }
  .searchselect.open .ss-toggle { border-color: var(--fi-accent); box-shadow: 0 0 0 3px rgba(246, 130, 31, 0.18); }
  .searchselect .ss-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
  .searchselect .ss-menu {
    display: none; position: absolute; left: 0; right: 0; top: 100%; margin-top: 4px; z-index: 25;
    background: var(--fi-surface); border: 1px solid var(--fi-line); border-radius: 8px; box-shadow: 0 4px 16px rgba(0,0,0,0.12);
    max-height: 240px; overflow: auto; padding: 6px;
  }
  .searchselect.open .ss-menu { display: block; }
  .searchselect .ss-menu input { width: 100%; margin-bottom: 4px; }
  .searchselect .ss-item { display: block; width: 100%; text-align: left; padding: 6px 8px; font-size: 0.8125rem; background: none; border: none; border-radius: 5px; cursor: pointer; }
  .searchselect .ss-item:hover { background: var(--fi-line-soft); }

  /* Searchable multi-select (typeahead: pills + search box, dropdown only while searching) */
  .multiselect { margin-bottom: 16px; }
  .multiselect-field { position: relative; }
  .multiselect-chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .multiselect-chips:not(:empty) { margin-top: 10px; }
  .multiselect-chip {
    background: var(--fi-accent-soft); color: var(--fi-amber); border: 1px solid #fed7aa;
    border-radius: 6px; padding: 3px 6px 3px 10px; font-size: 0.8125rem; display: flex; align-items: center; gap: 6px;
  }
  .multiselect-chip button { background: none; border: none; color: var(--fi-amber); padding: 0; cursor: pointer; font-size: 0.95rem; line-height: 1; }
  .multiselect-search { margin-bottom: 0 !important; }
  .multiselect-options {
    display: none; position: absolute; left: 0; right: 0; top: 100%; margin-top: 4px; z-index: 20;
    max-height: 220px; overflow-y: auto; background: var(--fi-surface); border: 1px solid var(--fi-line);
    border-radius: 8px; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.12); padding: 6px;
  }
  .multiselect-options.open { display: block; }
  .multiselect-option { display: block; font-weight: 400; font-size: 0.875rem; padding: 7px 8px; margin-bottom: 0; cursor: pointer; border-radius: 6px; color: var(--fi-body); }
  .multiselect-option:hover { background: var(--fi-line-soft); }
  .multiselect-option input { width: auto; margin: 0 6px 0 0; display: inline; vertical-align: middle; }
  .multiselect-option.hidden { display: none; }
  .multiselect-option.selected { display: none; }
  .multiselect-option-desc { color: var(--fi-muted); font-size: 0.78rem; padding-left: 22px; }
  .multiselect-badge {
    display: inline-block; margin-left: 6px; padding: 1px 7px; border-radius: 999px;
    background: var(--fi-amber-soft); color: var(--fi-amber); border: 1px solid #fcd34d;
    font-size: 0.6875rem; font-weight: 600; vertical-align: 1px;
  }

  /* Compact bulk-action bar that sits at the top of a list card */
  .bulk-bar { border-bottom: 1px solid var(--fi-line); padding-bottom: 12px; margin-bottom: 12px; }
  .bulk-bar-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin: 0; }
  .bulk-bar-count { white-space: nowrap; }
  button[disabled] { opacity: 0.5; cursor: not-allowed; }

  /* Profile photos */
  .avatar { border-radius: 50%; object-fit: cover; background: var(--fi-line-soft); border: 1px solid var(--fi-line); }
  .avatar-lg { width: 96px; height: 96px; }
  .avatar-sm { width: 28px; height: 28px; vertical-align: middle; margin-right: 8px; }
  .avatar-xs { width: 22px; height: 22px; vertical-align: middle; }
  /* Initials circle under the photo: the img covers it when it loads and hides
     itself when it 404s, so "no photo" needs no script. */
  .avatar-initials { position: relative; display: inline-flex; align-items: center; justify-content: center; font-weight: 600; color: #fff; background: hsl(var(--avatar-hue, 210) 40% 45%); overflow: hidden; text-transform: uppercase; user-select: none; }
  .avatar-initials img { position: absolute; inset: 0; width: 100%; height: 100%; margin: 0; border: 0; }
  .avatar-xs.avatar-initials { font-size: 9px; }
  .avatar-sm.avatar-initials { font-size: 11px; }
  .avatar-lg.avatar-initials { font-size: 34px; }
  .photo-upload-btn { font-size: 0.78rem; padding: 5px 12px; }

  /* Icon row actions (Iconoir) */
  .icon { display: block; flex-shrink: 0; }
  .icon-btn {
    display: inline-flex; align-items: center; justify-content: center; width: 30px; height: 30px; padding: 0;
    background: none; border: 1px solid transparent; border-radius: 6px; color: var(--fi-muted); cursor: pointer; text-decoration: none;
  }
  .icon-btn:hover { background: var(--fi-line-soft); color: var(--fi-ink); }
  .icon-btn:focus-visible { outline: none; border-color: var(--fi-accent); box-shadow: 0 0 0 3px rgba(246, 130, 31, 0.18); }
  .icon-btn-danger, .icon-btn-danger:hover { color: var(--fi-red); }
  .icon-btn-danger:hover { background: var(--fi-red-soft); }
  .row-actions { display: flex; gap: 2px; align-items: center; justify-content: flex-end; }
  .row-actions form { margin: 0; display: inline-flex; }
  /* Copy-to-clipboard buttons */
  .copy-btn {
    background: var(--fi-surface); color: var(--fi-body); border: 1px solid var(--fi-line-strong); border-radius: 6px;
    padding: 3px 10px; font-size: 0.75rem; cursor: pointer; white-space: nowrap; font-weight: 550;
  }
  .copy-btn:hover { background: var(--fi-line-soft); border-color: var(--fi-faint); }
  .copy-btn.copied { background: var(--fi-green-soft); color: var(--fi-green); border-color: #86efac; }
  .code-block { position: relative; }
  .code-block > .copy-btn { position: absolute; top: 8px; right: 8px; z-index: 1; }
  .code-block > pre { padding-right: 72px; }

  /* Prominent one-time secret display */
  .secret-block { background: var(--fi-amber-soft); border: 1px solid #fde68a; border-radius: var(--fi-radius); padding: 14px 16px; margin: 14px 0; }
  .secret-block-label { font-size: 0.75rem; font-weight: 650; color: var(--fi-amber); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 8px; }
  .secret-block-value { display: flex; align-items: center; gap: 10px; }
  .secret-block-value code { font-size: 0.9375rem; padding: 6px 10px; background: var(--fi-surface); border-color: #fde68a; }

  /* Expandable audit log rows */
  .audit-row { cursor: pointer; }
  .audit-row:hover { background: var(--fi-surface-2); }
  .audit-detail { display: none; }
  .audit-detail.open { display: table-row; }
  .audit-detail td { background: var(--fi-surface-2); padding: 10px 12px 14px 12px; }
  .audit-detail-content { font-size: 0.8125rem; color: var(--fi-body); display: flex; flex-direction: column; gap: 4px; }
  .audit-detail-content code { white-space: pre-wrap; word-break: break-all; }

  /* ------------------------------------------------------- confirm modal */
  dialog.fi-modal {
    border: none; border-radius: var(--fi-radius); padding: 0; max-width: 440px; width: calc(100% - 32px);
    box-shadow: 0 20px 60px rgba(15, 23, 42, 0.28); color: var(--fi-body);
  }
  dialog.fi-modal::backdrop { background: rgba(15, 23, 42, 0.45); }
  .fi-modal-body { padding: 22px 24px 8px; }
  .fi-modal-title { font-size: 1rem; font-weight: 650; color: var(--fi-ink); margin: 0 0 6px; }
  .fi-modal-text { font-size: 0.875rem; margin: 0; color: var(--fi-body); }
  .fi-modal-actions { display: flex; justify-content: flex-end; gap: 8px; padding: 16px 24px 20px; }

  /* Form footers: a primary action and a way back out of every form. */
  /* Every form's actions: one right-aligned row, destructive first, then Cancel, then the primary action - whatever the markup order. */
  .form-actions { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 10px; margin-top: 12px; }
  .form-actions > .danger, .form-actions > form { order: 1; }
  .form-actions > .secondary, .form-actions > a:not(.cancel) { order: 2; }
  .form-actions > .cancel { order: 3; }
  .form-actions > .primary { order: 4; }
  .form-actions > form { margin: 0; display: inline-flex; }
  .form-actions .cancel { color: var(--fi-muted); font-size: 0.875rem; font-weight: 550; }
  .form-actions .cancel:hover { color: var(--fi-ink); text-decoration: underline; }

  /* Read-only attribute grids (account profile, user detail). */
  .attr-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 0; }
  .attr {
    padding: 10px 14px 10px 0; border-bottom: 1px solid var(--fi-line-soft); min-width: 0;
  }
  .attr-label {
    font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.05em;
    color: var(--fi-muted); font-weight: 650; margin-bottom: 2px;
  }
  .attr-value { font-size: 0.875rem; color: var(--fi-ink); word-break: break-word; }
  .attr-value.empty { color: var(--fi-faint); }

  /* Dashboard charts (server-rendered SVG - no chart library, no fetch). */
  .chart { width: 100%; height: auto; display: block; overflow: visible; }
  .chart text { font-size: 11px; fill: var(--fi-muted); }
  .chart .gridline { stroke: var(--fi-line-soft); stroke-width: 1; }
  .chart .axis { stroke: var(--fi-line); stroke-width: 1; }
  .chart .bar { fill: var(--fi-accent); }
  .chart .bar.muted-bar { fill: var(--fi-line-strong); }
  .chart .area { fill: rgba(246, 130, 31, 0.14); }
  .chart .line { stroke: var(--fi-accent); stroke-width: 2; fill: none; }
  .chart .dot { fill: var(--fi-accent); }
  .chart-legend { display: flex; gap: 14px; flex-wrap: wrap; margin-top: 10px; }
  .chart-legend span { display: flex; align-items: center; gap: 6px; font-size: 0.6875rem; color: var(--fi-muted); }
  .chart-swatch { width: 10px; height: 10px; border-radius: 2px; }

  /* "Saved" success confirmation banner */
  .success-banner {
    background: var(--fi-green-soft); color: var(--fi-green); border: 1px solid #bbf7d0; border-radius: 8px;
    padding: 10px 14px; margin-bottom: 16px; font-size: 0.875rem; font-weight: 550;
  }
`;

const MULTISELECT_SCRIPT = `
function msSync(root) {
  const chipsEl = root.querySelector('.multiselect-chips');
  const boxes = [...root.querySelectorAll('input[type=checkbox]')];
  // Built as DOM nodes with textContent, never innerHTML: labels are user and
  // group names, which can arrive from the import API or SCIM carrying markup.
  chipsEl.replaceChildren(...boxes.filter(b => b.checked).map(b => {
    const chip = document.createElement('span');
    chip.className = 'multiselect-chip';
    chip.textContent = b.dataset.label;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = '\\u00d7';
    btn.addEventListener('click', () => { b.checked = false; msSync(root); });
    chip.appendChild(btn);
    return chip;
  }));
  root.querySelectorAll('.multiselect-option').forEach(opt => {
    const box = opt.querySelector('input[type=checkbox]');
    opt.classList.toggle('selected', box.checked);
  });
}
// data-remote: options come from the server as you type (large directories),
// keeping whatever is already ticked. data-max="1" makes it a single choice.
function msBind(root, b) {
  const input = root.querySelector('.multiselect-search');
  b.addEventListener('change', () => {
    if (root.dataset.max === '1' && b.checked) root.querySelectorAll('input[type=checkbox]').forEach(o => { if (o !== b) o.checked = false; });
    msSync(root);
    input.value = '';
    root.querySelector('.multiselect-options').classList.remove('open');
  });
}
const msTimers = new WeakMap();
function msRemote(input) {
  const root = input.closest('.multiselect');
  const term = input.value.trim();
  const optionsEl = root.querySelector('.multiselect-options');
  clearTimeout(msTimers.get(root));
  if (!term) { optionsEl.classList.remove('open'); return; }
  msTimers.set(root, setTimeout(async () => {
    const url = root.dataset.remote + (root.dataset.remote.includes('?') ? '&' : '?') + 'q=' + encodeURIComponent(term);
    let items = [];
    try { items = await (await fetch(url, { credentials: 'same-origin' })).json(); } catch (e) { items = []; }
    if (input.value.trim() !== term) return;
    optionsEl.querySelectorAll('.multiselect-option').forEach(o => { if (!o.querySelector('input').checked) o.remove(); else o.classList.add('hidden'); });
    const have = new Set([...optionsEl.querySelectorAll('input')].map(i => i.value));
    items.filter(it => !have.has(String(it.id))).forEach(it => {
      const label = document.createElement('label');
      label.className = 'multiselect-option';
      const box = document.createElement('input');
      box.type = 'checkbox'; box.name = root.dataset.name; box.value = String(it.id); box.dataset.label = it.label;
      label.append(box, document.createTextNode(' ' + it.label));
      (it.badges || []).forEach(function (bd) {
        const s = document.createElement('span');
        s.className = 'multiselect-badge';
        if (bd.title) s.title = bd.title;
        s.textContent = bd.label;
        label.appendChild(s);
      });
      if (it.desc) {
        const d = document.createElement('div');
        d.className = 'multiselect-option-desc';
        d.textContent = it.desc;
        label.appendChild(d);
      }
      optionsEl.appendChild(label);
      msBind(root, box);
    });
    if (!items.length) { const none = document.createElement('div'); none.className = 'multiselect-option muted'; none.textContent = 'No matches'; optionsEl.querySelectorAll('.muted').forEach(n => n.remove()); optionsEl.appendChild(none); }
    optionsEl.classList.add('open');
  }, 200));
}
function msFilter(input) {
  const root = input.closest('.multiselect');
  if (root.dataset.remote) return msRemote(input);
  const term = input.value.toLowerCase();
  const optionsEl = root.querySelector('.multiselect-options');
  optionsEl.classList.toggle('open', term.length > 0);
  root.querySelectorAll('.multiselect-option').forEach(opt => {
    const matches = opt.textContent.toLowerCase().includes(term);
    opt.classList.toggle('hidden', !matches);
  });
}
document.addEventListener('input', (e) => { if (e.target.matches('.multiselect-search')) msFilter(e.target); });
document.querySelectorAll('.multiselect').forEach(root => {
  msSync(root);
  root.querySelectorAll('input[type=checkbox]').forEach(b => msBind(root, b));
  document.addEventListener('click', (e) => {
    if (!root.contains(e.target)) root.querySelector('.multiselect-options').classList.remove('open');
  });
});
`;

const CONFIRM_SCRIPT = `
// One confirmation dialog for the whole console. Any form - or any individual
// submit button - carrying data-confirm is intercepted, and submits only when
// the dialog is accepted. Per-button attributes matter because several forms
// have a safe primary action and a destructive secondary one that posts
// elsewhere via formaction; only the latter should ask.
(function () {
  var dialog = document.getElementById("fi-confirm");
  if (!dialog) return;
  var titleEl = dialog.querySelector(".fi-modal-title");
  var textEl = dialog.querySelector(".fi-modal-text");
  var okBtn = dialog.querySelector(".fi-confirm-ok");
  var pendingForm = null;
  var pendingSubmitter = null;

  function settings(form, submitter) {
    if (submitter && submitter.dataset && submitter.dataset.confirm) return submitter.dataset;
    if (form.dataset && form.dataset.confirm) return form.dataset;
    return null;
  }

  function open(form, submitter, data) {
    pendingForm = form;
    pendingSubmitter = submitter || null;
    titleEl.textContent = data.confirmTitle || "Are you sure?";
    textEl.textContent = data.confirm || "";
    okBtn.textContent = data.confirmAction || "Confirm";
    okBtn.className = "fi-confirm-ok " + (data.confirmStyle === "danger" ? "danger" : "primary");
    if (typeof dialog.showModal === "function") dialog.showModal();
    else if (window.confirm(data.confirm || "Are you sure?")) submit();
  }

  function submit() {
    var form = pendingForm;
    var submitter = pendingSubmitter;
    pendingForm = null;
    pendingSubmitter = null;
    if (!form) return;
    // Clear whichever element asked, so the resubmission passes straight through.
    if (submitter && submitter.dataset) delete submitter.dataset.confirm;
    if (form.dataset) delete form.dataset.confirm;
    // requestSubmit(submitter) preserves formaction and the button's name/value.
    if (typeof form.requestSubmit === "function") form.requestSubmit(submitter || undefined);
    else form.submit();
  }

  document.addEventListener("submit", function (e) {
    var form = e.target;
    var submitter = e.submitter;
    var data = settings(form, submitter);
    if (!data) return;
    // data-confirm-when names a checkbox/radio that must be selected for the
    // confirmation to apply, for forms where only one option is destructive.
    if (data.confirmWhen) {
      var trigger = form.querySelector(data.confirmWhen);
      if (!trigger || !trigger.checked) return;
    }
    e.preventDefault();
    open(form, submitter, data);
  });

  okBtn.addEventListener("click", function () { dialog.close(); submit(); });
  dialog.querySelector(".fi-confirm-cancel").addEventListener("click", function () {
    pendingForm = null;
    pendingSubmitter = null;
    dialog.close();
  });
  dialog.addEventListener("close", function () { pendingForm = null; pendingSubmitter = null; });
})();
`;

const CONFIRM_DIALOG_HTML = `
<dialog class="fi-modal" id="fi-confirm">
  <div class="fi-modal-body">
    <p class="fi-modal-title">Are you sure?</p>
    <p class="fi-modal-text"></p>
  </div>
  <div class="fi-modal-actions">
    <button type="button" class="secondary fi-confirm-cancel">Cancel</button>
    <button type="button" class="primary fi-confirm-ok">Confirm</button>
  </div>
</dialog>
`;

const COPY_SCRIPT = `
function copyValue(btn) {
  const block = btn.closest(".code-block");
  const value = btn.dataset.copy ?? (block ? block.querySelector("pre").textContent : "");
  const original = btn.textContent;
  navigator.clipboard.writeText(value).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = original; btn.classList.remove('copied'); }, 1500);
  });
}
`;

/**
 * Row overflow menus (.rowmenu) and searchable single-selects (.searchselect).
 *
 * A searchselect is a <div class="searchselect"> containing one hidden input
 * (the submitted value), a .ss-toggle button showing the chosen label, and a
 * .ss-menu of .ss-item buttons carrying data-value/data-label. Selection is
 * just a value swap - no form submission - so callers re-render dependent
 * fields through their own onchange hooks.
 */
const UI_SCRIPT = `
// Declarative behaviours, wired once by delegation. These replace inline
// on*= attributes, which the Content-Security-Policy forbids: markup asks for a
// behaviour with a data- attribute instead.
//
//   data-autosubmit                 change submits the form (resetting ?page=1)
//   data-navigate="/path?x="        change navigates to that prefix + value;
//                                   with data-confirm-lost on the selected
//                                   <option>, asks first and reverts on cancel
//   data-append-template="tpl-id"   click clones <template id=tpl-id> ...
//     data-append-to="list-id"      ... into #list-id
//   data-remove-closest=".sel"      click removes the nearest ancestor .sel
//   data-mirror-prev                checkbox writes 1/0 into the hidden input
//                                   just before it (checkbox rows in arrays)
//   data-toggle-next="cls"          click toggles cls on the next sibling
//   data-show="id" / data-hide="id" click shows / hides #id
//   data-hide-on-error              an <img> that fails to load is hidden
(function () {
  document.addEventListener("change", function (e) {
    var el = e.target;
    if (el.matches("[data-autosubmit]")) {
      var page = el.form && el.form.querySelector("input[name=page]");
      if (page) page.value = 1;
      if (el.form.requestSubmit) el.form.requestSubmit(); else el.form.submit();
    } else if (el.matches("[data-navigate]")) {
      var opt = el.selectedOptions && el.selectedOptions[0];
      var lost = opt && opt.dataset.confirmLost;
      if (lost && !confirm("Moving to " + opt.text + " clears these attributes when you save: " + lost + ". Attributes with the same name carry over.")) {
        el.value = el.dataset.current || el.value;
        return;
      }
      location.href = el.dataset.navigate + encodeURIComponent(el.value);
    } else if (el.matches("[data-mirror-prev]")) {
      el.previousElementSibling.value = el.checked ? "1" : "0";
    }
  });
  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-append-template],[data-remove-closest],[data-toggle-next],[data-show],[data-hide],.copy-btn");
    if (!t) return;
    if (t.matches(".copy-btn")) return copyValue(t);
    if (t.dataset.appendTemplate) {
      document.getElementById(t.dataset.appendTo).appendChild(document.getElementById(t.dataset.appendTemplate).content.cloneNode(true));
    }
    if (t.dataset.removeClosest) { var row = t.closest(t.dataset.removeClosest); if (row) row.remove(); }
    if (t.dataset.toggleNext) t.nextElementSibling.classList.toggle(t.dataset.toggleNext);
    if (t.dataset.show) document.getElementById(t.dataset.show).style.display = "block";
    if (t.dataset.hide) document.getElementById(t.dataset.hide).style.display = "none";
  });
  // error does not bubble, so this listens in the capture phase.
  document.addEventListener("error", function (e) {
    if (e.target.matches && e.target.matches("img[data-hide-on-error]")) e.target.style.display = "none";
  }, true);
})();

(function () {
  document.addEventListener("click", function (e) {
    var menu = e.target.closest(".rowmenu");
    document.querySelectorAll(".rowmenu.open").forEach(function (m) { if (m !== menu) m.classList.remove("open"); });
    if (menu && e.target.closest("button")) menu.classList.toggle("open");
  });

  function ssClose(ss) { ss.classList.remove("open"); }
  document.addEventListener("click", function (e) {
    var ss = e.target.closest(".searchselect");
    document.querySelectorAll(".searchselect.open").forEach(function (o) { if (o !== ss) ssClose(o); });
    if (!ss) return;
    var toggle = e.target.closest(".ss-toggle");
    if (toggle) { ss.classList.toggle("open"); var q = ss.querySelector(".ss-menu input"); if (q) q.focus(); return; }
    var filter = e.target.closest(".ss-menu input");
    if (filter) return;
    var item = e.target.closest(".ss-item");
    if (item) {
      var input = ss.querySelector("input[type=hidden]");
      input.value = item.dataset.value;
      ss.querySelector(".ss-toggle .ss-label").textContent = item.dataset.label;
      ssClose(ss);
      input.dispatchEvent(new Event("change", { bubbles: true }));
    }
  });
  document.addEventListener("input", function (e) {
    if (!e.target.matches(".ss-menu input")) return;
    var q = e.target.value.toLowerCase();
    e.target.closest(".ss-menu").querySelectorAll(".ss-item").forEach(function (it) {
      it.style.display = it.textContent.toLowerCase().indexOf(q) === -1 ? "none" : "";
    });
  });
})();
`;

/**
 * Inline scripts allowed by the Content-Security-Policy.
 *
 * Every inline <script> FlareID emits goes through scriptTag(), which records
 * its exact text; the CSP then allows those texts by SHA-256 hash and nothing
 * else. The scripts are fixed strings in this codebase - never built from
 * request data - so the set is small and stable, and markup injected into a
 * page cannot ride on an allowance the way it could with a nonce stamped onto
 * every <script> after rendering.
 */
const INLINE_SCRIPTS = new Set<string>();
const SCRIPT_HASHES = new Map<string, string>();

export function scriptTag(js: string): string {
  INLINE_SCRIPTS.add(js);
  return `<script>${js}</script>`;
}

/** CSP source expressions ('sha256-...') for every inline script rendered so far. */
export async function inlineScriptHashes(): Promise<string[]> {
  for (const js of INLINE_SCRIPTS) {
    if (SCRIPT_HASHES.has(js)) continue;
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(js));
    SCRIPT_HASHES.set(js, `'sha256-${btoa(String.fromCharCode(...new Uint8Array(digest)))}'`);
  }
  return [...SCRIPT_HASHES.values()];
}

/** One-value typeahead: renders the .searchselect control; see UI_SCRIPT. */
export function searchSelect(
  name: string,
  options: { value: string; label: string }[],
  current: string,
  placeholder = "Select..."
): string {
  const currentLabel = options.find((o) => o.value === current)?.label ?? "";
  return `<div class="searchselect">
    <input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(current)}" />
    <button type="button" class="ss-toggle"><span class="ss-label">${escapeHtml(currentLabel || placeholder)}</span></button>
    <div class="ss-menu">
      <input type="text" placeholder="Search..." />
      ${options.map((o) => `<button type="button" class="ss-item" data-value="${escapeHtml(o.value)}" data-label="${escapeHtml(o.label)}">${escapeHtml(o.label)}</button>`).join("")}
    </div>
  </div>`;
}

/** "..." overflow menu on a table row. */
export function rowMenu(itemsHtml: string): string {
  return `<div class="rowmenu"><button type="button" aria-label="Row actions">&#8942;</button><div class="rowmenu-items">${itemsHtml}</div></div>`;
}

/**
 * Attributes that turn a form into a confirmed action, handled by the single
 * dialog rendered on every page. Replaces `onsubmit="return confirm(...)"`.
 */
export function confirmAttrs(
  message: string,
  opts: { title?: string; action?: string; danger?: boolean; when?: string } = {}
): string {
  return [
    `data-confirm="${escapeHtml(message)}"`,
    opts.title ? `data-confirm-title="${escapeHtml(opts.title)}"` : "",
    opts.action ? `data-confirm-action="${escapeHtml(opts.action)}"` : "",
    opts.danger ? `data-confirm-style="danger"` : "",
    // A CSS selector for a checkbox or radio inside the form: the dialog only
    // appears when it is selected, for forms where one option is destructive
    // and the rest are not.
    opts.when ? `data-confirm-when="${escapeHtml(opts.when)}"` : "",
  ]
    .filter(Boolean)
    .join(" ");
}

/** The way out of a form. Every form should have one. */
export function cancelLink(href: string, label = "Cancel"): string {
  return `<a class="cancel" href="${escapeHtml(href)}">${escapeHtml(label)}</a>`;
}

/**
 * A second submit button inside a form that posts somewhere else (Delete,
 * Rotate secret), so a form's every action shares its one action row. It
 * skips the form's validation; `confirm` is the confirmAttrs() string.
 */
export function formButton(label: string, formaction: string, opts: { variant?: "danger" | "secondary"; confirm?: string } = {}): string {
  return `<button class="${opts.variant ?? "secondary"}" type="submit" formaction="${escapeHtml(formaction)}" formnovalidate${opts.confirm ? ` ${opts.confirm}` : ""}>${escapeHtml(label)}</button>`;
}

/** Submit + cancel, laid out consistently at the foot of a form. */
export function formActions(submitLabel: string, cancelHref: string, opts: { danger?: boolean; end?: boolean } = {}): string {
  return `<div class="form-actions ${opts.end ? "end" : ""}">
    <button class="${opts.danger ? "danger" : "primary"}" type="submit">${escapeHtml(submitLabel)}</button>
    ${cancelLink(cancelHref)}
  </div>`;
}

/** One read-only attribute. Empty values are shown as a dash, not hidden. */
export function attr(label: string, value: string | number | null | undefined): string {
  const text = value === null || value === undefined || value === "" ? "" : String(value);
  return `<div class="attr">
    <div class="attr-label">${escapeHtml(label)}</div>
    <div class="attr-value ${text ? "" : "empty"}">${text ? escapeHtml(text) : "&mdash;"}</div>
  </div>`;
}

/** attr() for a value that is already rendered markup (e.g. ts()). */
export function attrHtml(label: string, html: string): string {
  return `<div class="attr">
    <div class="attr-label">${escapeHtml(label)}</div>
    <div class="attr-value">${html}</div>
  </div>`;
}

export function attrGrid(items: string[]): string {
  return `<div class="attr-grid">${items.join("")}</div>`;
}

export interface ChartPoint {
  label: string;
  value: number;
}

function niceCeiling(max: number): number {
  if (max <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(max));
  return Math.max(1, Math.ceil(max / magnitude) * magnitude);
}

/**
 * A server-rendered bar chart.
 *
 * Deliberately plain SVG built at render time: the console has no build step
 * and no client-side data fetching, and a charting library would be a larger
 * dependency than everything else here combined.
 */
export function barChart(points: ChartPoint[], opts: { height?: number; width?: number; muteWeekends?: boolean; barClass?: string } = {}): string {
  const width = opts.width ?? 640;
  const height = opts.height ?? 180;
  const pad = { top: 14, right: 8, bottom: 26, left: 34 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const max = niceCeiling(Math.max(...points.map((p) => p.value), 0));
  const band = plotW / Math.max(1, points.length);
  const barW = Math.min(28, band * 0.7);

  const gridlines = [0, 0.5, 1]
    .map((t) => {
      const y = pad.top + plotH - t * plotH;
      return `<line class="gridline" x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" />
              <text x="${pad.left - 6}" y="${y + 3}" text-anchor="end">${Math.round(max * t)}</text>`;
    })
    .join("");

  const bars = points
    .map((p, i) => {
      const h = max ? (p.value / max) * plotH : 0;
      const x = pad.left + i * band + (band - barW) / 2;
      const y = pad.top + plotH - h;
      return `<rect class="bar${opts.barClass ? ` ${opts.barClass}` : ""}" x="${x}" y="${y}" width="${barW}" height="${Math.max(0, h)}" rx="2">
                <title>${escapeHtml(p.label)}: ${p.value}</title>
              </rect>`;
    })
    .join("");

  // Label every nth bar so a month of days doesn't collide.
  const step = Math.ceil(points.length / 8) || 1;
  const labels = points
    .map((p, i) =>
      i % step === 0
        ? `<text x="${pad.left + i * band + band / 2}" y="${height - 10}" text-anchor="middle">${escapeHtml(p.label)}</text>`
        : ""
    )
    .join("");

  return `<svg class="chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="Bar chart">
    ${gridlines}${bars}${labels}
    <line class="axis" x1="${pad.left}" y1="${pad.top + plotH}" x2="${width - pad.right}" y2="${pad.top + plotH}" />
  </svg>`;
}

/**
 * Bars on a left-hand axis with a line overlaid on its own right-hand axis -
 * for pairing a big count (sign-ins) with a much smaller one (failures) that
 * would be invisible on the shared scale.
 */
export function barLineChart(
  bars: ChartPoint[],
  line: { name: string; className: string; values: number[] },
  opts: { height?: number; width?: number } = {}
): string {
  const width = opts.width ?? 640;
  const height = opts.height ?? 180;
  const pad = { top: 14, right: 36, bottom: 26, left: 34 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const maxBar = niceCeiling(Math.max(...bars.map((p) => p.value), 0));
  const maxLine = niceCeiling(Math.max(...line.values, 0));
  const band = plotW / Math.max(1, bars.length);
  const barW = Math.min(28, band * 0.7);
  const cx = (i: number) => pad.left + i * band + band / 2;
  const yLine = (v: number) => pad.top + plotH - (maxLine ? (v / maxLine) * plotH : 0);

  const grid = [0, 0.5, 1]
    .map((t) => {
      const y = pad.top + plotH - t * plotH;
      return `<line class="gridline" x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" />
              <text x="${pad.left - 6}" y="${y + 3}" text-anchor="end">${Math.round(maxBar * t)}</text>
              <text class="line-axis ${line.className}" x="${width - pad.right + 6}" y="${y + 3}" text-anchor="start">${Math.round(maxLine * t)}</text>`;
    })
    .join("");
  const rects = bars
    .map((p, i) => {
      const h = maxBar ? (p.value / maxBar) * plotH : 0;
      return `<rect class="bar" x="${cx(i) - barW / 2}" y="${pad.top + plotH - h}" width="${barW}" height="${Math.max(0, h)}" rx="2"><title>${escapeHtml(p.label)}: ${p.value}</title></rect>`;
    })
    .join("");
  // The line gets a card-coloured halo under it: where it crosses a bar the
  // colour stays readable instead of blending into the accent fill.
  const points = line.values.map((v, i) => `${cx(i).toFixed(1)},${yLine(v).toFixed(1)}`).join(" ");
  const poly =
    `<polyline class="line-halo" fill="none" points="${points}" />` +
    `<polyline class="line ${line.className}" fill="none" points="${points}" />` +
    line.values.map((v, i) => `<circle class="dot ${line.className} dot-halo" cx="${cx(i).toFixed(1)}" cy="${yLine(v).toFixed(1)}" r="2.5"><title>${escapeHtml(bars[i]?.label ?? "")} ${escapeHtml(line.name)}: ${v}</title></circle>`).join("");
  const step = Math.ceil(bars.length / 8) || 1;
  const labels = bars.map((p, i) => (i % step === 0 ? `<text x="${cx(i)}" y="${height - 10}" text-anchor="middle">${escapeHtml(p.label)}</text>` : "")).join("");

  return `<svg class="chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="Bar and line chart">${grid}${rects}${poly}${labels}
    <line class="axis" x1="${pad.left}" y1="${pad.top + plotH}" x2="${width - pad.right}" y2="${pad.top + plotH}" /></svg>`;
}

/** A server-rendered multi-series line chart (same conventions as barChart). */
export function lineChart(labels: string[], series: { name: string; className: string; values: number[] }[], opts: { height?: number; width?: number; unit?: string } = {}): string {
  const width = opts.width ?? 640;
  const height = opts.height ?? 200;
  const pad = { top: 14, right: 8, bottom: 26, left: 40 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const max = niceCeiling(Math.max(0, ...series.flatMap((s) => s.values)));
  const x = (i: number) => pad.left + (labels.length <= 1 ? plotW / 2 : (i / (labels.length - 1)) * plotW);
  const y = (v: number) => pad.top + plotH - (max ? (v / max) * plotH : 0);
  const unit = opts.unit ?? "";
  const grid = [0, 0.5, 1]
    .map((t) => `<line class="gridline" x1="${pad.left}" y1="${y(max * t)}" x2="${width - pad.right}" y2="${y(max * t)}" /><text x="${pad.left - 6}" y="${y(max * t) + 3}" text-anchor="end">${Math.round(max * t)}${unit}</text>`)
    .join("");
  const lines = series
    .map((s) => `<polyline class="line ${s.className}" fill="none" points="${s.values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ")}" />` +
      s.values.map((v, i) => `<circle class="dot ${s.className}" cx="${x(i).toFixed(1)}" cy="${y(v).toFixed(1)}" r="2"><title>${escapeHtml(labels[i] ?? "")} ${escapeHtml(s.name)}: ${v}${unit}</title></circle>`).join(""))
    .join("");
  const step = Math.ceil(labels.length / 8) || 1;
  const xl = labels.map((l, i) => (i % step === 0 ? `<text x="${x(i)}" y="${height - 10}" text-anchor="middle">${escapeHtml(l)}</text>` : "")).join("");
  return `<svg class="chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="Line chart">${grid}${lines}${xl}<line class="axis" x1="${pad.left}" y1="${pad.top + plotH}" x2="${width - pad.right}" y2="${pad.top + plotH}" /></svg>`;
}

/** Ranked horizontal bars, for "top N" breakdowns. */
export function rankedBars(points: ChartPoint[]): string {
  if (points.length === 0) return '<p class="muted">Nothing recorded yet.</p>';
  const max = Math.max(...points.map((p) => p.value), 1);
  return points
    .map(
      (p) => `<div style="margin-bottom:10px;">
        <div style="display:flex; justify-content:space-between; font-size:0.8125rem; margin-bottom:3px;">
          <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(p.label)}</span>
          <span class="muted" style="flex-shrink:0; margin-left:12px;">${p.value}</span>
        </div>
        <div style="height:8px; background:var(--fi-line-soft); border-radius:4px; overflow:hidden;">
          <div style="width:${(p.value / max) * 100}%; height:100%; background:var(--fi-accent); border-radius:4px;"></div>
        </div>
      </div>`
    )
    .join("");
}

/**
 * A read-only block of data (JSON, logs, snippets) with a Copy button pinned
 * top-right. The button copies the <pre>'s live text, so blocks that scripts
 * append to copy what's currently shown.
 */
export function codeBlock(value: string, opts: { id?: string; className?: string; style?: string } = {}): string {
  return `<div class="code-block"><button type="button" class="copy-btn">Copy</button><pre${opts.id ? ` id="${escapeHtml(opts.id)}"` : ""}${opts.className === "" ? "" : ` class="${escapeHtml(opts.className ?? "import-log")}"`}${opts.style ? ` style="${escapeHtml(opts.style)}"` : ""}>${escapeHtml(value)}</pre></div>`;
}

/**
 * Icons from Iconoir (https://iconoir.com, MIT licence), inlined as SVG so
 * they need no request and no CSP allowance. Rule of thumb for the console:
 * per-row actions in tables and lists are icon buttons; actions on a whole
 * form or section (Save, Cancel, Delete this client) stay text buttons.
 */
const ICON_PATHS = {
  trash: [
    "M20 9L18.005 20.3463C17.8369 21.3026 17.0062 22 16.0353 22H7.96474C6.99379 22 6.1631 21.3026 5.99496 20.3463L4 9",
    "M21 6L15.375 6M3 6L8.625 6M8.625 6V4C8.625 2.89543 9.52043 2 10.625 2H13.375C14.4796 2 15.375 2.89543 15.375 4V6M8.625 6L15.375 6",
  ],
  edit: [
    "M14.3632 5.65156L15.8431 4.17157C16.6242 3.39052 17.8905 3.39052 18.6716 4.17157L20.0858 5.58579C20.8668 6.36683 20.8668 7.63316 20.0858 8.41421L18.6058 9.8942M14.3632 5.65156L4.74749 15.2672C4.41542 15.5993 4.21079 16.0376 4.16947 16.5054L3.92738 19.2459C3.87261 19.8659 4.39148 20.3848 5.0115 20.33L7.75191 20.0879C8.21972 20.0466 8.65806 19.8419 8.99013 19.5099L18.6058 9.8942M14.3632 5.65156L18.6058 9.8942",
  ],
  xmark: ["M6.75827 17.2426L12.0009 12M17.2435 6.75736L12.0009 12M12.0009 12L6.75827 6.75736M12.0009 12L17.2435 17.2426"],
  plus: ["M6 12H12M18 12H12M12 12V6M12 12V18"],
  logOut: [
    "M12 12H19M19 12L16 15M19 12L16 9",
    "M19 6V5C19 3.89543 18.1046 3 17 3H7C5.89543 3 5 3.89543 5 5V19C5 20.1046 5.89543 21 7 21H17C18.1046 21 19 20.1046 19 19V18",
  ],
  refresh: [
    "M21.1679 8C19.6247 4.46819 16.1006 2 11.9999 2C6.81459 2 2.55104 5.94668 2.04932 11",
    "M17 8H21.4C21.7314 8 22 7.73137 22 7.4V3",
    "M2.88146 16C4.42458 19.5318 7.94874 22 12.0494 22C17.2347 22 21.4983 18.0533 22 13",
    "M7.04932 16H2.64932C2.31795 16 2.04932 16.2686 2.04932 16.6V21",
  ],
  navRight: ["M9 6L15 12L9 18"],
  eye: ["M3 13C6.6 5 17.4 5 21 13", "M12 17C10.3431 17 9 15.6569 9 14C9 12.3431 10.3431 11 12 11C13.6569 11 15 12.3431 15 14C15 15.6569 13.6569 17 12 17Z"],
} as const;
export type IconName = keyof typeof ICON_PATHS;

export function icon(name: IconName, size = 16): string {
  return `<svg class="icon" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${ICON_PATHS[name].map((d) => `<path d="${d}"/>`).join("")}</svg>`;
}

/** A row action as an icon: the label is its accessible name and tooltip. `danger` paints it red. */
export function iconButton(name: IconName, label: string, opts: { danger?: boolean; type?: "submit" | "button"; attrs?: string } = {}): string {
  return `<button type="${opts.type ?? "submit"}" class="icon-btn${opts.danger ? " icon-btn-danger" : ""}" aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}"${opts.attrs ? ` ${opts.attrs}` : ""}>${icon(name)}</button>`;
}

/** The same, as a link (Edit, Preview). `newTab` opens it in a new tab. */
export function iconLink(href: string, name: IconName, label: string, opts: { newTab?: boolean } = {}): string {
  return `<a href="${escapeHtml(href)}" class="icon-btn" aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}"${opts.newTab ? ' target="_blank" rel="noopener"' : ""}>${icon(name)}</a>`;
}

/** Row actions as icons on one line, right-aligned: forms inside sit inline. */
export function rowActions(...items: string[]): string {
  return `<div class="row-actions">${items.filter(Boolean).join("")}</div>`;
}

/** A small inline "Copy" button that copies `value` to the clipboard on click. */
export function copyButton(value: string, label = "Copy"): string {
  return `<button type="button" class="copy-btn" data-copy="${escapeHtml(value)}">${escapeHtml(label)}</button>`;
}

/**
 * A prominent, highlighted box for a secret that's only ever shown once
 * (client secrets, temp passwords, backup codes) - impossible to miss, with
 * a one-click copy button right next to the value.
 */
export function secretBlock(label: string, value: string): string {
  return `
    <div class="secret-block">
      <div class="secret-block-label">${escapeHtml(label)} - copy this now, it won't be shown again</div>
      <div class="secret-block-value">
        <code>${escapeHtml(value)}</code>
        ${copyButton(value)}
      </div>
    </div>
  `;
}

/** A dismissible green success banner, e.g. for showing "Saved" after a redirect-on-save. */
export function successBanner(message: string): string {
  return `<div class="success-banner">${escapeHtml(message)}</div>`;
}

/** "Ada Chen" -> "AC", "cher" -> "CH", "" -> "?". */
export function initialsFor(displayName: string, fallback = ""): string {
  const parts = (displayName.trim() || fallback.trim()).split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  return parts.length === 1 ? parts[0]!.slice(0, 2).toUpperCase() : (parts[0]![0]! + parts[parts.length - 1]![0]!).toUpperCase();
}

/** The same name always lands on the same tint, so a list reads consistently. */
function avatarHue(seed: string): number {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) % 360;
  return h;
}

/**
 * A person's avatar: their photo when they have one, their initials in a
 * tinted circle when they do not. The initials sit under the <img>, which
 * hides itself on a 404 - no script or extra query needed for the fallback.
 */
export function avatar(userId: number, displayName: string, size: "xs" | "sm" | "lg" = "sm", opts: { upn?: string; v?: string } = {}): string {
  const name = displayName || opts.upn || "Account";
  const src = `/account/photo/${userId}${opts.v ? `?v=${encodeURIComponent(opts.v)}` : ""}`;
  return `<span class="avatar avatar-${size} avatar-initials" style="--avatar-hue:${avatarHue(name)};" role="img" aria-label="${escapeHtml(name)}">${escapeHtml(initialsFor(displayName, opts.upn))}<img src="${src}" alt="" class="avatar avatar-${size}" data-hide-on-error /></span>`;
}

/** The initials circle on its own, for a spot that already knows there is no photo. */
export function avatarInitials(displayName: string, size: "xs" | "sm" | "lg" = "xs"): string {
  const name = displayName || "Account";
  return `<span class="avatar avatar-${size} avatar-initials" style="--avatar-hue:${avatarHue(name)};" aria-hidden="true">${escapeHtml(initialsFor(displayName))}</span>`;
}

/** A searchable, chip-based multi-select built from plain checkboxes (no build step, works everywhere). */
export function multiSelect(
  name: string,
  options: { id: number | string; label: string }[],
  selectedIds: Set<number | string>,
  placeholder = "Search..."
): string {
  // Search first, then the current selection. A group with thirty members
  // pushed the search box off the bottom of the card, which is exactly when you
  // need it. The dropdown is anchored to the field rather than the whole
  // component so it still opens directly beneath what you are typing into.
  return `
    <div class="multiselect">
      <div class="multiselect-field">
        <input type="text" class="multiselect-search" placeholder="${escapeHtml(placeholder)}" />
        <div class="multiselect-options">
          ${options
            .map(
              (o) =>
                `<label class="multiselect-option ${selectedIds.has(o.id) ? "selected" : ""}"><input type="checkbox" name="${escapeHtml(name)}" value="${escapeHtml(String(o.id))}" data-label="${escapeHtml(o.label)}" ${selectedIds.has(o.id) ? "checked" : ""} /> ${escapeHtml(o.label)}</label>`
            )
            .join("")}
        </div>
      </div>
      <div class="multiselect-chips"></div>
    </div>
  `;
}

/**
 * A multiSelect whose options are fetched from `url` (?q=...) as the user types:
 * for pickers over the whole directory. `selected` is the current value(s).
 * `single` allows one choice (posted as one field, or none when cleared).
 */
export function remoteMultiSelect(name: string, url: string, selected: { id: number | string; label: string }[], placeholder = "Search people...", single = false): string {
  return `
    <div class="multiselect" data-remote="${escapeHtml(url)}" data-name="${escapeHtml(name)}"${single ? ' data-max="1"' : ""}>
      <div class="multiselect-field">
        <input type="text" class="multiselect-search" placeholder="${escapeHtml(placeholder)}" autocomplete="off" />
        <div class="multiselect-options">
          ${selected.map((o) => `<label class="multiselect-option hidden"><input type="checkbox" name="${escapeHtml(name)}" value="${escapeHtml(String(o.id))}" data-label="${escapeHtml(o.label)}" checked /> ${escapeHtml(o.label)}</label>`).join("")}
        </div>
      </div>
      <div class="multiselect-chips"></div>
    </div>
  `;
}

/** Page-size <select> that auto-submits its enclosing GET form (resetting to page 1). */
export function pageSizeSelect(current: number, options: number[] = [20, 50, 100]): string {
  return `<select name="pageSize" data-autosubmit style="width:auto; display:inline-block; margin-bottom:0;">
    ${options.map((n) => `<option value="${n}" ${n === current ? "selected" : ""}>${n} / page</option>`).join("")}
  </select>`;
}

/** Prev/Next + page indicator, preserving any extra query params (e.g. search, pageSize). */
export function paginationControls(basePath: string, page: number, totalPages: number, extraParams: Record<string, string | number> = {}): string {
  if (totalPages <= 1) return "";
  const qs = (p: number) => {
    const params = new URLSearchParams({ ...Object.fromEntries(Object.entries(extraParams).map(([k, v]) => [k, String(v)])), page: String(p) });
    return `${basePath}?${params.toString()}`;
  };
  return `<div class="row between" style="margin-top:12px;">
    <span class="muted">Page ${page} of ${totalPages}</span>
    <div style="display:flex; gap:8px;">
      ${page > 1 ? `<a href="${qs(page - 1)}"><button class="secondary" type="button">Previous</button></a>` : `<button class="secondary" type="button" disabled>Previous</button>`}
      ${page < totalPages ? `<a href="${qs(page + 1)}"><button class="secondary" type="button">Next</button></a>` : `<button class="secondary" type="button" disabled>Next</button>`}
    </div>
  </div>`;
}

export interface Breadcrumb {
  label: string;
  href?: string;
}

export function breadcrumbs(items: Breadcrumb[]): string {
  return `<div class="breadcrumbs">
    ${items
      .map((item, i) => {
        const isLast = i === items.length - 1;
        const crumb = item.href && !isLast ? `<a href="${escapeHtml(item.href)}">${escapeHtml(item.label)}</a>` : `<span>${escapeHtml(item.label)}</span>`;
        return i === 0 ? crumb : ` <span class="breadcrumb-sep">/</span> ${crumb}`;
      })
      .join("")}
  </div>`;
}

/** Applies the stored theme before first paint; "system" (nothing stored) follows prefers-color-scheme. */
const THEME_INIT_SCRIPT = `(function(){try{var t=localStorage.getItem("fi-theme");if(t==="dark"||t==="light")document.documentElement.setAttribute("data-theme",t);}catch(e){}})();`;

/** The top-bar toggle cycles system -> dark -> light -> system. */
const THEME_TOGGLE_SCRIPT = `(function(){
  var bs=document.querySelectorAll("[data-theme-toggle]"); if(!bs.length) return;
  var order=["system","dark","light"];
  function cur(){try{return localStorage.getItem("fi-theme")||"system";}catch(e){return "system";}}
  var icons={
    system:'<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.25" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8 1.75A6.25 6.25 0 018 14.25z" fill="currentColor"/></svg>',
    dark:'<svg viewBox="0 0 16 16" aria-hidden="true" fill="currentColor"><path d="M13.7 9.6A6 6 0 116.4 2.3a.5.5 0 01.7.6 5 5 0 006 6 .5.5 0 01.6.7z"/></svg>',
    light:'<svg viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="3" fill="currentColor" stroke="none"/><path d="M8 1v1.6M8 13.4V15M1 8h1.6M13.4 8H15M3 3l1.1 1.1M11.9 11.9L13 13M13 3l-1.1 1.1M4.1 11.9L3 13"/></svg>'
  };
  function label(){var k=cur();var a={system:"auto",dark:"dark",light:"light"}[k];bs.forEach(function(b){b.innerHTML='<span style="display:inline-flex;vertical-align:-2px;margin-right:8px;">'+icons[k]+'</span>Theme';b.setAttribute("aria-label","Theme: "+a);});}
  bs.forEach(function(b){b.addEventListener("click",function(){
    var next=order[(order.indexOf(cur())+1)%order.length];
    try{ if(next==="system") localStorage.removeItem("fi-theme"); else localStorage.setItem("fi-theme",next);}catch(e){}
    if(next==="system") document.documentElement.removeAttribute("data-theme"); else document.documentElement.setAttribute("data-theme",next);
    label();
  });});
  label();
})();`;

/**
 * Rewrites every <time class="ts"> to the browser's locale. The console
 * timezone override rides along on the top bar's data-tz attribute; an
 * invalid or unset value falls back to the browser's own zone. The ISO
 * instant stays in the title so the exact UTC moment is always a hover away.
 */
const TS_SCRIPT = `(function(){
  var bar=document.querySelector('.topbar'),tz=bar?(bar.getAttribute('data-tz')||''):'';
  if(tz){try{new Intl.DateTimeFormat('en',{timeZone:tz});}catch(e){tz='';}}
  var dt={dateStyle:'medium',timeStyle:'short'},dd={dateStyle:'medium'};
  if(tz){dt.timeZone=tz;dd.timeZone=tz;dt.timeZoneName='short';}
  var fmt=new Intl.DateTimeFormat(undefined,dt),dfmt=new Intl.DateTimeFormat(undefined,dd);
  var els=document.querySelectorAll('time.ts');
  for(var i=0;i<els.length;i++){
    var d=new Date(els[i].getAttribute('datetime'));
    if(isNaN(d.getTime()))continue;
    els[i].textContent=(els[i].hasAttribute('data-date-only')?dfmt:fmt).format(d);
  }
})();`;

/** Top-bar dropdowns (account menu, notifications): one opens at a time, clicks outside close them. */
const NAV_MENU_SCRIPT = `(function(){
  document.addEventListener('click', function(e){
    var btn = e.target.closest ? e.target.closest('.nav-menu-btn') : null;
    document.querySelectorAll('.nav-menu.open').forEach(function(m){ if (btn && m.contains(btn)) return; m.classList.remove('open'); });
    if (btn) btn.parentElement.classList.toggle('open');
  });
  document.addEventListener('keydown', function(e){ if (e.key === 'Escape') document.querySelectorAll('.nav-menu.open').forEach(function(m){ m.classList.remove('open'); }); });
})();`;

/** The top bar. `logoUrl` is the brand's uploaded logo (brands.ts); FlareID's icon without one. */
/** One row of the notifications dropdown: something a signed-in person can act on. */
export interface TopNotification {
  label: string;
  href: string;
  when?: string;
}

/** What the bell carries: pending work for this person, newest first. */
export interface NotificationFeed {
  count: number;
  items: TopNotification[];
  /** Where "see all" points; defaults to the first item's href. */
  seeAllHref?: string;
}

/** The top bar's theme switch; THEME_TOGGLE_SCRIPT (added by page() whenever there is a top bar) wires it up. */
export const THEME_TOGGLE_BUTTON = `<button class="nav-item theme-toggle" type="button" data-theme-toggle title="Switch between light, dark and system theme" aria-label="Theme: auto"><svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.25" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8 1.75A6.25 6.25 0 018 14.25z" fill="currentColor"/></svg></button>`;

/** The (?) beside a console page's title, opening its guide under /docs in a new tab. */
export function helpLink(href: string, topic: string): string {
  return `<a class="help-link" href="${escapeHtml(href)}" target="_blank" rel="noopener" title="Help: ${escapeHtml(topic)}" aria-label="Help: ${escapeHtml(topic)} (opens in a new tab)">?</a>`;
}

const CARET = '<svg viewBox="0 0 16 16" width="10" height="10" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6l4 4 4-4"/></svg>';
const BELL = '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 2a4 4 0 00-4 4v2.2l-1.2 2.6a.6.6 0 00.55.9h9.3a.6.6 0 00.55-.9L12 8.2V6a4 4 0 00-4-4z"/><path d="M6.5 13.5a1.75 1.75 0 003 0"/></svg>';

export function nav(appName: string, isAdmin: boolean, logoUrl?: string | null, tz = "", notifications?: NotificationFeed | null, userName = "", avatarSrc = ""): string {
  const bell = notifications
    ? `<div class="nav-menu" data-nav-menu>
        <button class="nav-menu-btn notif-btn" type="button" aria-label="Notifications${notifications.count ? ` - ${notifications.count} pending` : ""}" title="Things needing your attention">${BELL}${notifications.count ? `<span class="notif-dot">${notifications.count > 99 ? "99+" : notifications.count}</span>` : ""}</button>
        <div class="nav-menu-list">
          ${notifications.items.length ? notifications.items.map((i) => `<a class="notif-item" href="${escapeHtml(i.href)}">${escapeHtml(i.label)}${i.when ? `<span class="notif-when">${escapeHtml(i.when)}</span>` : ""}</a>`).join("") : '<div class="notif-empty">Nothing needs your attention.</div>'}
          ${notifications.count > notifications.items.length ? `<a class="notif-item" href="${escapeHtml(notifications.seeAllHref ?? notifications.items[0]?.href ?? "/admin/access")}">See all ${notifications.count} &rarr;</a>` : ""}
        </div>
      </div>`
    : "";
  return `<header class="topbar"${tz ? ` data-tz="${escapeHtml(tz)}"` : ""}>
    <div class="brand-row">
    <a href="/" class="brand">
      <img src="${escapeHtml(logoUrl || "/FlareID_Icon.png")}" alt="" class="brand-logo${logoUrl ? " brand-logo-custom" : ""}" data-hide-on-error />
      <span class="brand-name">${escapeHtml(appName)}</span>
      <span class="brand-tagline"><span class="brand-version">v${VERSION}</span></span>
    </a>
      <a class="github-link" href="https://github.com/securitypedant/flareid" target="_blank" rel="noopener noreferrer" title="FlareID on GitHub" aria-label="FlareID on GitHub">
        <svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      </a>
    </div>
    <nav>
      ${bell}
      <span class="nav-links">
        <a href="/account">Account</a>
        <a href="/account/applications">Applications</a>
        <a href="/account/access">Access</a>
        <a href="/account/security">Security</a>
      </span>
      ${isAdmin ? '<span class="nav-links"><a href="/admin" class="nav-admin">Admin</a></span>' : ""}
      <div class="nav-menu nav-burger" data-nav-menu>
        <button class="nav-menu-btn" type="button" aria-haspopup="true" aria-label="Menu"><svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M2 4h12M2 8h12M2 12h12"/></svg></button>
        <div class="nav-menu-list">
          <a href="/account">Account</a>
          <a href="/account/applications">Applications</a>
          <a href="/account/access">Access</a>
          <a href="/account/security">Security</a>
          ${isAdmin ? '<a href="/admin" class="nav-admin">Admin</a>' : ""}
          <hr class="nav-menu-divider" />
          ${THEME_TOGGLE_BUTTON}
          <form method="POST" action="/logout" style="margin:0;"><button class="nav-item signout" type="submit">Sign out</button></form>
        </div>
      </div>
      <div class="nav-menu nav-user" data-nav-menu>
        <button class="nav-menu-btn" type="button" aria-haspopup="true">${avatarSrc ? `<img src="${escapeHtml(avatarSrc)}" alt="" class="avatar avatar-xs" data-hide-on-error />` : avatarInitials(userName)}<span class="nav-menu-name">${escapeHtml(userName || "Account")}</span> ${CARET}</button>
        <div class="nav-menu-list">
          ${THEME_TOGGLE_BUTTON}
          <hr class="nav-menu-divider" />
          <form method="POST" action="/logout" style="margin:0;"><button class="nav-item signout" type="submit">Sign out</button></form>
        </div>
      </div>
    </nav>
  </header>`;
}

/** Titles for the shared error card, by HTTP status. */
const ERROR_TITLES: Record<number, string> = {
  400: "That didn't work",
  403: "Not allowed",
  404: "Not found",
  409: "Already exists",
  429: "Too many requests",
  503: "Not available",
};

const GO_BACK_SCRIPT = `document.querySelectorAll("[data-go-back]").forEach(function (b) {
  b.addEventListener("click", function (e) { if (history.length > 1) { e.preventDefault(); history.back(); } });
});`;

/**
 * The card every refused action shows in the signed-in pages: a title, the
 * reason, and a way back. "Go back" uses the browser history, so a form keeps
 * what was typed into it; without history it follows `backHref`.
 */
export function errorCard(status: number, message: string, backHref: string): string {
  const title = ERROR_TITLES[status] ?? "Something went wrong";
  return `<section class="card error-card" role="alert">
    <h2 style="margin-top:0;">${escapeHtml(title)}</h2>
    <p class="error" style="font-size:0.9375rem;">${escapeHtml(message)}</p>
    <div class="form-actions" style="justify-content:flex-start;">
      <a href="${escapeHtml(backHref)}" data-go-back><button class="primary" type="button">Go back</button></a>
    </div>
    ${scriptTag(GO_BACK_SCRIPT)}
  </section>`;
}

/** The error card as a whole page with the top bar, for routes outside the admin console layout. */
export function errorPage(appName: string, status: number, message: string, backHref: string, isAdmin: boolean, logoUrl?: string | null): string {
  return page(ERROR_TITLES[status] ?? "Something went wrong", `<div style="max-width:640px; margin:32px auto;">${errorCard(status, message, backHref)}</div>`, appName, false, nav(appName, isAdmin, logoUrl));
}

/**
 * An error for whoever asked: the styled card for a browser (no top bar - the
 * person may not be signed in), plain text for an API client or script.
 */
export function errorResponse(request: Request, appName: string, status: number, message: string): Response {
  const path = new URL(request.url).pathname;
  const machine = /^\/(api|scim)\//.test(path) || ["/token", "/userinfo", "/introspect", "/revoke", "/jwks.json"].includes(path);
  const wantsHtml = (request.headers.get("Accept") ?? "").includes("text/html");
  if (machine || !wantsHtml) return new Response(message, { status, headers: { "Content-Type": "text/plain; charset=UTF-8" } });
  const body = page(ERROR_TITLES[status] ?? "Something went wrong", `<div style="max-width:640px; margin:48px auto;">${errorCard(status, message, safeBackHref(request, "/"))}</div>`, appName);
  return new Response(body, { status, headers: { "Content-Type": "text/html; charset=UTF-8" } });
}

/** Where "Go back" leads when there is no history: the page the request came from, if it is ours. */
export function safeBackHref(request: Request, fallback: string): string {
  const ref = request.headers.get("Referer");
  try {
    if (ref && new URL(ref).origin === new URL(request.url).origin) {
      const u = new URL(ref);
      return u.pathname + u.search;
    }
  } catch {
    // fall through
  }
  return fallback;
}

export function page(
  title: string,
  bodyHtml: string,
  appName: string,
  wide = false,
  navHtml = "",
  extraStyles = "",
  extraBodyHtml = "",
  /** Extra <head> markup after the styles: the auth pages' custom stylesheet <link>. */
  headHtml = "",
  /** The page's language and direction: the sign-in pages' negotiated locale; the console is English. */
  lang: { code: string; dir: "ltr" | "rtl" } = { code: "en", dir: "ltr" }
): string {
  // Pages without the top bar are the branded sign-in pages: always light.
  const themed = Boolean(navHtml);
  // The centred card (the sign-in pages) is the page's main landmark; the
  // console's wide layout is left as it is.
  const main = wide ? `<div class="page-wrap">${bodyHtml}</div>` : `<main class="center-wrap"><div class="card">${bodyHtml}</div></main>`;
  return `<!doctype html>
<html lang="${escapeHtml(lang.code)}" dir="${lang.dir === "rtl" ? "rtl" : "ltr"}"${themed ? "" : ' data-theme="light"'}>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)} - ${escapeHtml(appName)}</title>
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png" />
  <link rel="icon" type="image/png" sizes="48x48" href="/favicon-48.png" />
  ${themed ? scriptTag(THEME_INIT_SCRIPT) : ""}
  <style>${STYLES}</style>
  ${extraStyles ? `<style>${extraStyles}</style>` : ""}
  ${headHtml}
</head>
<body>
  ${navHtml}
  ${extraBodyHtml}
  ${main}
  ${CONFIRM_DIALOG_HTML}
  ${scriptTag(MULTISELECT_SCRIPT)}
  ${scriptTag(COPY_SCRIPT)}
  ${scriptTag(CONFIRM_SCRIPT)}
  ${scriptTag(UI_SCRIPT)}
  ${navHtml ? scriptTag(THEME_TOGGLE_SCRIPT) : ""}
  ${navHtml ? scriptTag(TS_SCRIPT) : ""}
  ${navHtml ? scriptTag(NAV_MENU_SCRIPT) : ""}
</body>
</html>`;
}

/** Wraps admin/account page bodies in the standard "card" container. */
export function cardSection(innerHtml: string): string {
  return `<div class="card">${innerHtml}</div>`;
}

/**
 * A timestamp rendered in the *browser's* locale (and the admin-configured
 * console timezone when one is set, see settings.ts). The ISO instant is
 * emitted in datetime; TS_SCRIPT rewrites the text client-side. The visible
 * fallback is the UTC instant so a no-JS page still shows a correct time.
 */
export function ts(iso: string | null | undefined, opts: { dateOnly?: boolean } = {}): string {
  if (!iso) return '<span class="muted">&mdash;</span>';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '<span class="muted">&mdash;</span>';
  const stamp = d.toISOString();
  const fallback = `${stamp.slice(0, 10)} ${stamp.slice(11, 16)} UTC`;
  return `<time class="ts" datetime="${stamp}"${opts.dateOnly ? " data-date-only" : ""} title="${stamp}">${escapeHtml(opts.dateOnly ? stamp.slice(0, 10) : fallback)}</time>`;
}
