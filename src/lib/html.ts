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
    --fi-amber: #92400e;
    --fi-amber-soft: #fffbeb;
    --fi-radius: 10px;
  }

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
  .header-meta { font-size: 0.875rem; font-weight: 400; color: var(--fi-muted); margin-left: 10px; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; align-items: start; margin-bottom: 18px; }
  .two-col .card { margin-bottom: 0; }
  @media (max-width: 860px) { .two-col { grid-template-columns: 1fr; } }

  .breadcrumbs { font-size: 0.8125rem; color: var(--fi-muted); margin-bottom: 6px; }
  .breadcrumbs a { color: var(--fi-muted); text-decoration: none; }
  .breadcrumbs a:hover { color: var(--fi-accent); text-decoration: underline; }
  .breadcrumbs span:last-child { color: var(--fi-body); font-weight: 500; }
  .breadcrumb-sep { color: #cbd5e1; margin: 0 4px; }

  /* ------------------------------------------------------------- forms */
  label { display: block; font-size: 0.8125rem; font-weight: 600; margin-bottom: 5px; color: var(--fi-ink); }
  input[type=text], input[type=email], input[type=password], input[type=number], input[type=date], select, textarea {
    width: 100%; padding: 9px 12px; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 0.875rem;
    box-sizing: border-box; margin-bottom: 16px; font-family: inherit; color: var(--fi-ink); background: var(--fi-surface);
    transition: border-color 0.12s, box-shadow 0.12s;
  }
  input::placeholder, textarea::placeholder { color: #94a3b8; }
  input:focus, select:focus, textarea:focus {
    outline: none; border-color: var(--fi-accent); box-shadow: 0 0 0 3px rgba(246, 130, 31, 0.18);
  }
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

  button {
    padding: 8px 15px; border-radius: 8px; border: 1px solid transparent; font-size: 0.875rem;
    cursor: pointer; font-weight: 550; font-family: inherit; transition: background 0.12s, border-color 0.12s;
  }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .primary { background: var(--fi-accent); color: #fff; }
  .primary:hover:not(:disabled) { background: var(--fi-accent-dark); }
  .secondary { background: var(--fi-surface); color: var(--fi-body); border-color: #cbd5e1; }
  .secondary:hover:not(:disabled) { background: var(--fi-line-soft); border-color: #94a3b8; }
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
    font-weight: 650; background: #fbfcfd; border-bottom-color: var(--fi-line);
  }
  tbody tr:hover { background: #fbfcfd; }
  tr:last-child td { border-bottom: none; }

  /* ------------------------------------------------------------- state */
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.6875rem;
    font-weight: 650; letter-spacing: 0.01em; border: 1px solid transparent;
  }
  .badge-active { background: var(--fi-green-soft); color: var(--fi-green); border-color: #bbf7d0; }
  .badge-disabled { background: var(--fi-red-soft); color: var(--fi-red); border-color: #fecaca; }
  .badge-revoked { background: var(--fi-red-soft); color: var(--fi-red); border-color: #fecaca; }
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
  .stat-card:hover { text-decoration: none; }
  .stat-card .card { text-align: left; transition: border-color 0.12s, box-shadow 0.12s; }
  .stat-card:hover .card { border-color: var(--fi-accent); box-shadow: 0 2px 10px rgba(246, 130, 31, 0.14); }
  .stat-card h2 { font-size: 2rem; margin: 0; color: var(--fi-ink); font-weight: 300; letter-spacing: -0.02em; }
  .stat-card p {
    margin: 2px 0 0 0; color: var(--fi-muted); font-size: 0.6875rem;
    text-transform: uppercase; letter-spacing: 0.05em; font-weight: 650;
  }

  /* --------------------------------------------------------- section nav */
  .admin-tabs {
    display: flex; gap: 2px; margin-bottom: 22px; flex-wrap: wrap;
    border-bottom: 1px solid var(--fi-line);
  }
  .admin-tabs a {
    padding: 9px 14px; text-decoration: none; font-size: 0.875rem; font-weight: 550;
    background: transparent; color: var(--fi-muted); border: none;
    border-bottom: 2px solid transparent; margin-bottom: -1px; border-radius: 6px 6px 0 0;
  }
  .admin-tabs a:hover { background: var(--fi-line-soft); color: var(--fi-ink); text-decoration: none; }
  .admin-tabs a.active { background: transparent; color: var(--fi-accent); border-bottom-color: var(--fi-accent); }

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

  /* Copy-to-clipboard buttons */
  .copy-btn {
    background: var(--fi-surface); color: var(--fi-body); border: 1px solid #cbd5e1; border-radius: 6px;
    padding: 3px 10px; font-size: 0.75rem; cursor: pointer; white-space: nowrap; font-weight: 550;
  }
  .copy-btn:hover { background: var(--fi-line-soft); border-color: #94a3b8; }
  .copy-btn.copied { background: var(--fi-green-soft); color: var(--fi-green); border-color: #86efac; }

  /* Prominent one-time secret display */
  .secret-block { background: var(--fi-amber-soft); border: 1px solid #fde68a; border-radius: var(--fi-radius); padding: 14px 16px; margin: 14px 0; }
  .secret-block-label { font-size: 0.75rem; font-weight: 650; color: var(--fi-amber); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 8px; }
  .secret-block-value { display: flex; align-items: center; gap: 10px; }
  .secret-block-value code { font-size: 0.9375rem; padding: 6px 10px; background: var(--fi-surface); border-color: #fde68a; }

  /* Expandable audit log rows */
  .audit-row { cursor: pointer; }
  .audit-row:hover { background: #fbfcfd; }
  .audit-detail { display: none; }
  .audit-detail.open { display: table-row; }
  .audit-detail td { background: #fbfcfd; padding: 10px 12px 14px 12px; }
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
  .form-actions { display: flex; align-items: center; gap: 10px; margin-top: 4px; }
  .form-actions.end { justify-content: flex-end; }
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
  .attr-value.empty { color: #94a3b8; }

  /* Dashboard charts (server-rendered SVG - no chart library, no fetch). */
  .chart { width: 100%; height: auto; display: block; overflow: visible; }
  .chart text { font-size: 10px; fill: var(--fi-muted); }
  .chart .gridline { stroke: var(--fi-line-soft); stroke-width: 1; }
  .chart .axis { stroke: var(--fi-line); stroke-width: 1; }
  .chart .bar { fill: var(--fi-accent); }
  .chart .bar.muted-bar { fill: #cbd5e1; }
  .chart .area { fill: rgba(246, 130, 31, 0.14); }
  .chart .line { stroke: var(--fi-accent); stroke-width: 2; fill: none; }
  .chart .dot { fill: var(--fi-accent); }
  .chart-legend { display: flex; gap: 14px; flex-wrap: wrap; margin-top: 10px; }
  .chart-legend span { display: flex; align-items: center; gap: 6px; font-size: 0.75rem; color: var(--fi-muted); }
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
  chipsEl.innerHTML = boxes.filter(b => b.checked).map(b =>
    '<span class="multiselect-chip">' + b.dataset.label + '<button type="button" data-id="' + b.value + '">\\u00d7</button></span>'
  ).join('');
  chipsEl.querySelectorAll('button').forEach(btn => {
    btn.addEventListener('click', () => {
      const box = boxes.find(b => b.value === btn.dataset.id);
      if (box) { box.checked = false; msSync(root); }
    });
  });
  root.querySelectorAll('.multiselect-option').forEach(opt => {
    const box = opt.querySelector('input[type=checkbox]');
    opt.classList.toggle('selected', box.checked);
  });
}
function msFilter(input) {
  const root = input.closest('.multiselect');
  const term = input.value.toLowerCase();
  const optionsEl = root.querySelector('.multiselect-options');
  optionsEl.classList.toggle('open', term.length > 0);
  root.querySelectorAll('.multiselect-option').forEach(opt => {
    const matches = opt.textContent.toLowerCase().includes(term);
    opt.classList.toggle('hidden', !matches);
  });
}
document.querySelectorAll('.multiselect').forEach(root => {
  msSync(root);
  const input = root.querySelector('.multiselect-search');
  root.querySelectorAll('input[type=checkbox]').forEach(b => b.addEventListener('change', () => {
    msSync(root);
    input.value = '';
    root.querySelector('.multiselect-options').classList.remove('open');
  }));
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
  const value = btn.dataset.copy;
  const original = btn.textContent;
  navigator.clipboard.writeText(value).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = original; btn.classList.remove('copied'); }, 1500);
  });
}
`;

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
export function barChart(points: ChartPoint[], opts: { height?: number; muteWeekends?: boolean } = {}): string {
  const width = 640;
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
      return `<rect class="bar" x="${x}" y="${y}" width="${barW}" height="${Math.max(0, h)}" rx="2">
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

/** A small inline "Copy" button that copies `value` to the clipboard on click. */
export function copyButton(value: string, label = "Copy"): string {
  return `<button type="button" class="copy-btn" data-copy="${escapeHtml(value)}" onclick="copyValue(this)">${escapeHtml(label)}</button>`;
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
        <input type="text" class="multiselect-search" placeholder="${escapeHtml(placeholder)}" oninput="msFilter(this)" />
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

/** Page-size <select> that auto-submits its enclosing GET form (resetting to page 1). */
export function pageSizeSelect(current: number, options: number[] = [20, 50, 100]): string {
  return `<select name="pageSize" onchange="this.closest('form').querySelector('input[name=page]') && (this.closest('form').querySelector('input[name=page]').value = 1); this.form.submit();" style="width:auto; display:inline-block; margin-bottom:0;">
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

export function nav(appName: string, isAdmin: boolean): string {
  return `<header class="topbar">
    <a href="/" class="brand">
      <img src="/FlareID_Icon.png" alt="" class="brand-logo" onerror="this.style.display='none'" />
      <span class="brand-name">${escapeHtml(appName)}</span>
      <span class="brand-tagline">Open source, Cloudflare hosted IDP</span>
    </a>
    <nav>
      <a href="/account">My account</a>
      ${isAdmin ? '<a href="/admin">Admin</a>' : ""}
      <form method="POST" action="/logout" style="display:inline"><button class="link-button signout" type="submit">Sign out</button></form>
    </nav>
  </header>`;
}

export function page(
  title: string,
  bodyHtml: string,
  appName: string,
  wide = false,
  navHtml = "",
  extraStyles = "",
  extraBodyHtml = ""
): string {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)} - ${escapeHtml(appName)}</title>
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png" />
  <link rel="icon" type="image/png" sizes="48x48" href="/favicon-48.png" />
  <style>${STYLES}</style>
  ${extraStyles ? `<style>${extraStyles}</style>` : ""}
</head>
<body>
  ${navHtml}
  ${extraBodyHtml}
  ${wide ? `<div class="page-wrap">${bodyHtml}</div>` : `<div class="center-wrap"><div class="card">${bodyHtml}</div></div>`}
  ${CONFIRM_DIALOG_HTML}
  <script>${MULTISELECT_SCRIPT}</script>
  <script>${COPY_SCRIPT}</script>
  <script>${CONFIRM_SCRIPT}</script>
</body>
</html>`;
}

/** Wraps admin/account page bodies in the standard "card" container. */
export function cardSection(innerHtml: string): string {
  return `<div class="card">${innerHtml}</div>`;
}
