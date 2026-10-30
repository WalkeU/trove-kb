// Trove browser UI. Authentication credentials live only in HttpOnly
// cookies managed by the server. JavaScript reads a separate CSRF value,
// never the access token, refresh token or password after submission.

import { parse, filterPaths, classifyDiffLine } from "./md.js";
import { el, appendText, appendEscaped, renderBlocks, readHref } from "./render.js";

const API = "../v1/";
const AUTH = "../auth/";
const IDLE_MS = 30 * 60 * 1000;
const state = {
  authenticated: false,
  setupRequired: false,
  httpAllowed: false,
  role: "",
  actor: "",
  files: [],
  fileSet: new Set(),
  commit: "",
  lastActive: Date.now(),
  shown: null,
  seq: 0,
};
let refreshing = null;
const $ = (id) => document.getElementById(id);

class ApiError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details || [];
  }
}

function csrfToken() {
  const prefix = location.protocol === "https:" ? "__Host-trove-csrf=" : "trove-http-csrf=";
  const cookie = document.cookie.split(";").map((s) => s.trim()).find((s) => s.startsWith(prefix));
  return cookie ? cookie.slice(prefix.length) : "";
}

function transportAllowed() { return location.protocol === "https:" || state.httpAllowed; }

function lock(message) {
  state.authenticated = false;
  state.role = "";
  state.actor = "";
  state.files = [];
  state.fileSet = new Set();
  state.shown = null;
  state.seq++;
  $("view").replaceChildren();
  $("tree").replaceChildren();
  $("app").hidden = true;
  $("nav").hidden = true;
  $("who").hidden = true;
  $("lock").hidden = true;
  $("menu").hidden = true;
  $("login").hidden = false;
  $("login-error").textContent = message || "";
  for (const id of ["owner-token", "password", "password-confirm"]) $(id).value = "";
  $("password").focus();
}

async function request(base, method, path, body, extraHeaders = {}) {
  const headers = { Accept: "application/json", ...extraHeaders };
  if (method !== "GET" && method !== "HEAD") headers["X-Trove-CSRF"] = csrfToken();
  const init = { method, headers, credentials: "same-origin", cache: "no-store", redirect: "error", referrerPolicy: "same-origin", mode: "same-origin" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let response;
  try { response = await fetch(base + path, init); }
  catch { throw new ApiError(0, "network error"); }
  let data = null;
  if ((response.headers.get("Content-Type") || "").startsWith("application/json")) {
    try { data = await response.json(); } catch { /* handled below */ }
  }
  if (!response.ok) {
    throw new ApiError(response.status, (data && typeof data.error === "string" && data.error) || "HTTP " + response.status, data && Array.isArray(data.details) ? data.details : []);
  }
  if (data === null) throw new ApiError(response.status, "unexpected response type");
  return data;
}

function authRequest(method, path, body, headers) {
  return request(AUTH, method, path, body, headers);
}

async function refreshSession() {
  if (!refreshing) {
    refreshing = authRequest("POST", "refresh", {}).finally(() => { refreshing = null; });
  }
  return refreshing;
}

async function api(method, path, body) {
  try { return await request(API, method, path, body); }
  catch (error) {
    if (error.status !== 401 || !state.authenticated) throw error;
    try {
      await refreshSession();
      return await request(API, method, path, body);
    } catch (refreshError) {
      lock("Your session expired. Sign in again.");
      throw refreshError;
    }
  }
}

async function enterApp() {
  state.authenticated = true;
  const status = await api("GET", "status");
  state.role = status.role;
  state.actor = status.actor;
  $("login").hidden = true;
  $("app").hidden = false;
  $("nav").hidden = false;
  $("lock").hidden = false;
  $("menu").hidden = false;
  $("who").replaceChildren();
  appendText($("who"), status.actor + " (" + status.role + ")");
  $("who").hidden = false;
  $("nav-review").hidden = status.role !== "approver";
  setPending(status.pending);
  touch();
  await loadTree();
  route();
}

async function signIn() {
  if (!transportAllowed()) {
    $("login-error").textContent = "This server requires HTTPS to sign in. Open the HTTPS address.";
    return;
  }
  const button = $("login-btn");
  button.disabled = true;
  $("login-error").textContent = "";
  const password = $("password").value;
  const confirm = $("password-confirm").value;
  const ownerToken = $("owner-token").value.trim();
  try {
    if (state.setupRequired) {
      if (!ownerToken) throw new Error("Enter the owner token for the first setup.");
      if (password !== confirm) throw new Error("The passwords do not match.");
      await authRequest("POST", "setup", { password, password_confirm: confirm }, { Authorization: "Bearer " + ownerToken });
      state.setupRequired = false;
    } else {
      await authRequest("POST", "login", { password });
    }
    for (const id of ["owner-token", "password", "password-confirm"]) $(id).value = "";
    await enterApp();
  } catch (error) {
    lock(error.message);
    await loadAuthState(false);
  } finally {
    button.disabled = !transportAllowed();
  }
}

async function signOut(message = "Signed out.") {
  try { await authRequest("POST", "logout", {}); }
  catch { /* the page must also lock when its server session is gone */ }
  lock(message);
  await loadAuthState(false);
}

async function loadAuthState(restore) {
  try {
    const info = await authRequest("GET", "state");
    state.setupRequired = info.setup_required === true;
    state.httpAllowed = info.http_allowed === true;
    $("setup-fields").hidden = !state.setupRequired;
    $("confirm-fields").hidden = !state.setupRequired;
    $("login-description").textContent = state.setupRequired
      ? "Create your owner password. The owner token is needed only for this first setup."
      : "Sign in with your owner password.";
    $("password").autocomplete = state.setupRequired ? "new-password" : "current-password";
    $("login-btn").textContent = state.setupRequired ? "Create password" : "Sign in";
    $("login-btn").disabled = !transportAllowed();
    $("https-note").hidden = transportAllowed();
    const restoring = restore && !state.setupRequired && transportAllowed();
    // The sign-in form stays hidden while a stored session is being checked,
    // so a signed-in user never sees it flash.
    if (!restoring) $("login").hidden = false;
    if (restoring) {
      try { await authRequest("GET", "session"); }
      catch (error) {
        if (error.status !== 401 || !csrfToken()) throw error;
        await refreshSession();
      }
      await enterApp();
    }
  } catch (error) {
    if (restore && error.status === 401) lock("");
    else {
      if ($("app").hidden) $("login").hidden = false;
      $("login-error").textContent = error.message;
    }
  }
}

function touch() { state.lastActive = Date.now(); }

setInterval(() => {
  if (state.authenticated && Date.now() - state.lastActive > IDLE_MS) signOut("Signed out after 30 minutes without activity.");
}, 30 * 1000);

function q(params) {
  return new URLSearchParams(params).toString();
}

function setPending(n) {
  const c = $("pending-count");
  c.textContent = n > 0 ? String(n) : "";
}

// ---- small view helpers ----

function errorBox(e) {
  const box = el("div", "banner error");
  appendText(box, e && e.message ? e.message : String(e));
  if (e && e.details && e.details.length) {
    const ul = el("ul");
    for (const d of e.details) ul.appendChild(el("li", null, String(d)));
    box.appendChild(ul);
  }
  return box;
}

function short(id) {
  return String(id || "").slice(0, 12);
}

function fmtTime(s) {
  if (!s || s.startsWith("0001-")) return "";
  const d = new Date(s);
  return isNaN(d) ? String(s) : d.toLocaleString();
}

function setView(...nodes) {
  $("view").replaceChildren(...nodes);
  $("view").scrollTop = 0;
  window.scrollTo(0, 0);
}

function closeMenu() {
  document.body.classList.remove("side-open");
  $("menu").setAttribute("aria-expanded", "false");
}

// ---- tree ----

async function loadTree() {
  const t = await api("GET", "tree");
  state.files = Array.isArray(t.files) ? t.files.filter((f) => typeof f === "string") : [];
  state.fileSet = new Set(state.files);
  state.commit = t.commit || "";
  renderTree();
}

function buildTree(paths) {
  const root = { dirs: new Map(), files: [] };
  for (const p of paths) {
    const parts = p.split("/");
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!node.dirs.has(parts[i])) node.dirs.set(parts[i], { dirs: new Map(), files: [] });
      node = node.dirs.get(parts[i]);
    }
    node.files.push(p);
  }
  return root;
}

function fileLink(path, label) {
  const a = el("a", "file");
  a.href = readHref(path);
  a.dataset.path = path;
  appendText(a, label);
  a.title = path;
  return a;
}

function treeNode(node, depth) {
  const frag = document.createDocumentFragment();
  for (const name of [...node.dirs.keys()].sort()) {
    const d = el("details");
    if (depth === 0 && node.dirs.size <= 3) d.open = true;
    const s = el("summary", null, name);
    d.appendChild(s);
    d.appendChild(treeNode(node.dirs.get(name), depth + 1));
    frag.appendChild(d);
  }
  const ul = el("ul");
  for (const f of node.files.sort()) {
    const li = el("li");
    li.appendChild(fileLink(f, f.slice(f.lastIndexOf("/") + 1)));
    ul.appendChild(li);
  }
  if (node.files.length) frag.appendChild(ul);
  return frag;
}

function renderTree() {
  const tree = $("tree");
  const filter = $("filter").value;
  if (filter.trim()) {
    const ul = el("ul", "flat");
    const hits = filterPaths(state.files, filter);
    for (const f of hits) {
      const li = el("li");
      li.appendChild(fileLink(f, f));
      ul.appendChild(li);
    }
    tree.replaceChildren(hits.length ? ul : el("p", "muted", "No file name matches."));
  } else if (state.files.length === 0) {
    tree.replaceChildren(el("p", "muted", "The knowledge base is empty."));
  } else {
    tree.replaceChildren(treeNode(buildTree(state.files), 0));
  }
  markCurrent();
}

function markCurrent() {
  const cur = currentPath();
  for (const a of $("tree").querySelectorAll("a.file")) {
    if (a.dataset.path === cur) {
      a.setAttribute("aria-current", "page");
      let p = a.parentElement;
      while (p && p !== $("tree")) {
        if (p.tagName === "DETAILS") p.open = true;
        p = p.parentElement;
      }
    } else {
      a.removeAttribute("aria-current");
    }
  }
}

// ---- routing ----

function parseHash() {
  const h = location.hash.replace(/^#/, "");
  const [pathPart, query = ""] = h.split("?");
  const segs = pathPart.split("/").filter((s) => s !== "");
  let dec;
  try {
    dec = segs.map(decodeURIComponent);
  } catch {
    dec = [];
  }
  return { segs: dec, query: new URLSearchParams(query) };
}

function currentPath() {
  const { segs } = parseHash();
  return segs[0] === "read" ? segs.slice(1).join("/") : "";
}

async function route() {
  if (!state.authenticated) return;
  touch();
  closeMenu();
  const seq = ++state.seq;
  const { segs, query } = parseHash();
  state.shown = null;
  $("nav-read").classList.toggle("active", segs[0] !== "review" && segs[0] !== "account");
  $("nav-account").classList.toggle("active", segs[0] === "account");
  $("nav-review").classList.toggle("active", segs[0] === "review");
  markCurrent();
  try {
    if (segs[0] === "read" && segs.length > 1) {
      await showFile(seq, segs.slice(1).join("/"), query.get("view") === "source");
    } else if (segs[0] === "search") {
      await showSearch(seq, query.get("q") || "");
    } else if (segs[0] === "account") {
      showAccount();
    } else if (segs[0] === "review" && state.role === "approver") {
      if (segs[1]) await showReview(seq, segs[1]);
      else await showPending(seq);
    } else {
      showHome();
    }
  } catch (e) {
    if (seq === state.seq && state.authenticated) setView(errorBox(e));
  }
}

function showHome() {
  const box = el("div", "home");
  box.appendChild(el("h1", null, "Knowledge base"));
  const p = el("p", "muted");
  appendText(p, state.files.length + " file(s) at commit " + short(state.commit) + ". Pick a file on the left, filter by name or search the content.");
  box.appendChild(p);
  const index = ["INDEX.md", "README.md", "index.md"].find((f) => state.fileSet.has(f));
  if (index) {
    const go = el("p");
    go.appendChild(fileLink(index, "Open " + index));
    box.appendChild(go);
  }
  setView(box);
}

function showAccount() {
  const box = el("div", "account");
  box.appendChild(el("h1", null, "Account"));
  box.appendChild(el("p", "muted", "Changing your password signs out every device."));
  const fields = [];
  for (const [label, autocomplete] of [["Current password", "current-password"], ["New password (15 to 128 characters)", "new-password"], ["New password again", "new-password"]]) {
    const row = el("label", "account-field", label);
    const input = el("input");
    input.type = "password";
    input.autocomplete = autocomplete;
    row.appendChild(input);
    fields.push(input);
    box.appendChild(row);
  }
  const message = el("div");
  const save = el("button", "btn primary", "Change password");
  save.type = "button";
  save.addEventListener("click", async () => {
    save.disabled = true;
    message.replaceChildren();
    try {
      await api("GET", "status");
      await authRequest("POST", "password", { current_password: fields[0].value, password: fields[1].value, password_confirm: fields[2].value });
      fields.forEach((input) => { input.value = ""; });
      lock("Password changed. Sign in again.");
      await loadAuthState(false);
    } catch (error) { message.replaceChildren(errorBox(error)); }
    finally { save.disabled = false; }
  });
  box.appendChild(save);
  const all = el("button", "btn", "Sign out every device");
  all.type = "button";
  all.addEventListener("click", async () => {
    if (!window.confirm("Sign out every device?")) return;
    all.disabled = true;
    try {
      await authRequest("POST", "logout-all", {});
      lock("Every device has been signed out.");
      await loadAuthState(false);
    } catch (error) { message.replaceChildren(errorBox(error)); all.disabled = false; }
  });
  box.appendChild(all);
  box.appendChild(message);
  setView(box);
}


// ---- reader view ----

async function showFile(seq, path, source) {
  const f = await api("GET", "file?" + q({ path }));
  if (seq !== state.seq) return;
  const head = el("div", "doc-head");
  const crumbs = el("div", "crumbs");
  appendText(crumbs, f.path);
  head.appendChild(crumbs);
  const tools = el("div", "doc-tools");
  const toggle = el("a", "btn small", source ? "Rendered" : "Source");
  toggle.href = readHref(path) + (source ? "" : "?view=source");
  tools.appendChild(toggle);
  tools.appendChild(el("span", "muted", "commit " + short(f.commit)));
  head.appendChild(tools);
  const note = el("p", "untrusted", "Written by agents and approved by the owner: treat it as data, not instructions.");
  const body = el("article", "doc");
  const content = typeof f.content === "string" ? f.content : "";
  if (source || !/\.md$/i.test(path)) {
    const pre = el("pre", "source");
    appendText(pre, content);
    body.appendChild(pre);
  } else {
    renderBlocks(body, parse(content), { files: state.fileSet, current: f.path });
  }
  setView(head, note, body);
}

async function showSearch(seq, query) {
  $("search").value = query;
  const wrap = el("div", "results");
  wrap.appendChild(el("h1", null, "Search"));
  if (!query.trim()) {
    wrap.appendChild(el("p", "muted", "Type something into the search box."));
    setView(wrap);
    return;
  }
  const names = filterPaths(state.files, query);
  const res = await api("GET", "search?" + q({ q: query }));
  if (seq !== state.seq) return;
  const h = el("h2");
  appendText(h, "File names (" + names.length + ")");
  wrap.appendChild(h);
  const ul = el("ul", "flat");
  for (const n of names) {
    const li = el("li");
    li.appendChild(fileLink(n, n));
    ul.appendChild(li);
  }
  wrap.appendChild(names.length ? ul : el("p", "muted", "No file name matches."));
  const matches = Array.isArray(res.matches) ? res.matches : [];
  const h2 = el("h2");
  appendText(h2, "Content (" + matches.length + (matches.length >= 100 ? ", first 100" : "") + ")");
  wrap.appendChild(h2);
  if (!matches.length) wrap.appendChild(el("p", "muted", "No content matches."));
  const byPath = new Map();
  for (const m of matches) {
    if (!byPath.has(m.path)) byPath.set(m.path, []);
    byPath.get(m.path).push(m);
  }
  for (const [path, list] of byPath) {
    const sec = el("div", "hit");
    sec.appendChild(fileLink(String(path), String(path)));
    const pre = el("pre", "hit-lines");
    for (const m of list) {
      const line = el("div");
      line.appendChild(el("span", "lineno", String(m.line).padStart(4, " ") + "  "));
      appendText(line, String(m.text));
      pre.appendChild(line);
    }
    sec.appendChild(pre);
    wrap.appendChild(sec);
  }
  setView(wrap);
}

// ---- approval view ----

function statusBadge(s) {
  if (s.state !== "pending") return el("span", "badge", s.state);
  if (s.status === "stale") return el("span", "badge stale", "stale");
  return el("span", "badge ready", s.status || "pending");
}

async function showPending(seq) {
  const list = await api("GET", "proposals?" + q({ state: "pending" }));
  if (seq !== state.seq) return;
  setPending(list.length);
  const wrap = el("div", "pending");
  const h = el("h1");
  appendText(h, "Pending proposals (" + list.length + ")");
  wrap.appendChild(h);
  wrap.appendChild(el("p", "muted", "Open a proposal to see its full diff. Each proposal is approved on its own, with its own digest."));
  if (!list.length) wrap.appendChild(el("p", "muted", "Nothing to review."));
  for (const s of list) {
    const a = el("a", "card");
    a.href = "#/review/" + encodeURIComponent(s.id);
    const top = el("div", "card-top");
    top.appendChild(statusBadge(s));
    top.appendChild(el("span", "topic", s.topic));
    a.appendChild(top);
    const meta = el("div", "card-meta muted");
    appendText(meta, short(s.id) + " · " + s.agent + " · " + (s.files || []).length + " file(s)" + " · submitted " + fmtTime(s.submitted_at));
    a.appendChild(meta);
    const flags = [];
    if ((s.warnings || []).length) flags.push(s.warnings.length + " warning(s)");
    if (s.overlap_count) flags.push("overlaps " + s.overlap_count + " other proposal(s)");
    if (s.supersedes) flags.push("rebased from " + short(s.supersedes));
    if (flags.length) a.appendChild(el("div", "card-flags", flags.join(" · ")));
    wrap.appendChild(a);
  }
  setView(wrap);
}

function metaRow(dl, k, v) {
  if (v === undefined || v === null || v === "") return;
  dl.appendChild(el("dt", null, k));
  const dd = el("dd");
  if (v instanceof Node) dd.appendChild(v);
  else appendText(dd, String(v));
  dl.appendChild(dd);
}

function renderDiff(text) {
  const pre = el("pre", "diff");
  const lines = String(text).split("\n");
  if (lines.length && lines[lines.length - 1] === "") lines.pop();
  for (const line of lines) {
    const row = el("div", "dl " + classifyDiffLine(line));
    appendEscaped(row, line === "" ? " " : line);
    pre.appendChild(row);
  }
  return pre;
}

// fullFile offers the whole modified file next to the diff hunks. The
// lines are built on first open so a long review stays light.
function fullFile(text) {
  const d = el("details", "full-file");
  d.appendChild(el("summary", null, "Open the whole modified file"));
  d.addEventListener("toggle", () => {
    if (d.open && d.childElementCount === 1) d.appendChild(renderFull(text));
  });
  return d;
}

function renderFull(text) {
  const pre = el("pre", "diff full");
  const lines = String(text).split("\n");
  if (lines.length && lines[lines.length - 1] === "") lines.pop();
  lines.forEach((line, i) => {
    const row = el("div", "dl ctx");
    row.appendChild(el("span", "ln", String(i + 1)));
    appendEscaped(row, line === "" ? " " : line);
    pre.appendChild(row);
  });
  return pre;
}

async function showReview(seq, id) {
  const rv = await api("GET", "proposals/" + encodeURIComponent(id) + "/review");
  if (seq !== state.seq) return;
  renderReview(rv, seq);
}

function renderReview(rv, seq) {
  const s = rv.summary;
  const snapshot = JSON.stringify(rv);
  state.shown = { id: s.id, digest: s.digest, snapshot };
  const wrap = el("div", "review");

  const back = el("a", "back", "All pending proposals");
  back.href = "#/review";
  wrap.appendChild(back);

  const h = el("h1", "topic");
  appendText(h, s.topic);
  wrap.appendChild(h);
  wrap.appendChild(el("p", "untrusted", rv.notice));

  const dl = el("dl", "meta");
  metaRow(dl, "proposal", s.id);
  metaRow(dl, "agent", s.agent);
  metaRow(dl, "state", statusBadge(s));
  metaRow(dl, "base", s.base);
  if (s.supersedes) metaRow(dl, "supersedes", s.supersedes + " (earlier reviews do not carry over)");
  if ((s.scope || []).length) metaRow(dl, "scope", s.scope.join(", "));
  metaRow(dl, "submitted", fmtTime(s.submitted_at));
  metaRow(dl, "expires", fmtTime(s.expires_at));
  metaRow(dl, "loaded", new Date().toLocaleTimeString());
  wrap.appendChild(dl);

  const alerts = el("div", "alerts");
  for (const f of s.stale_files || []) alerts.appendChild(el("div", "banner error", "STALE: " + f + " changed since base"));
  for (const o of s.overlaps || []) alerts.appendChild(el("div", "banner warn", "OVERLAP: pending proposal " + o + " touches the same file(s)"));
  if ((s.warnings || []).length) {
    const box = el("div", "banner warn");
    box.appendChild(el("strong", null, "Warnings"));
    const ul = el("ul");
    for (const w of s.warnings) ul.appendChild(el("li", null, w));
    box.appendChild(ul);
    alerts.appendChild(box);
  }
  wrap.appendChild(alerts);

  const files = rv.files || [];
  const fh = el("h2");
  appendText(fh, "Changes (" + files.length + " file(s), shown in full)");
  wrap.appendChild(fh);
  for (const f of files) {
    const sec = el("section", "file-diff");
    const t = el("h3");
    t.appendChild(el("span", "op op-" + (f.new ? "new" : f.op), f.new ? "new" : f.op));
    appendText(t, " " + f.path);
    sec.appendChild(t);
    sec.appendChild(renderDiff(f.diff));
    if (f.full) sec.appendChild(fullFile(f.full));
    wrap.appendChild(sec);
  }

  const dg = el("div", "digest");
  dg.appendChild(el("div", "fm-label", "digest"));
  dg.appendChild(el("code", "digest-value", s.digest));
  wrap.appendChild(dg);

  if (s.state === "pending") wrap.appendChild(decisionPanel(s, seq));
  setView(wrap);
}

function decisionPanel(s, seq) {
  const panel = el("div", "decide");
  const status = el("div", "decide-status", "");
  status.setAttribute("role", "status");

  // Approve
  const ap = el("div", "approve-box");
  ap.appendChild(el("h2", null, "Approve"));
  if (s.status === "stale") {
    ap.appendChild(el("p", "banner error", "This proposal is stale (a touched file changed since its base). It cannot be approved; the agent has to rebase it."));
  }
  const lbl = el("label", "check");
  const cb = el("input");
  cb.type = "checkbox";
  lbl.appendChild(cb);
  appendText(lbl, " I have read the complete diff above.");
  ap.appendChild(lbl);
  const btn = el("button", "btn primary", "Approve digest " + short(s.digest));
  btn.type = "button";
  btn.disabled = true;
  cb.addEventListener("change", () => {
    btn.disabled = !cb.checked || s.status === "stale";
  });
  btn.addEventListener("click", () => approve(btn, cb, status, seq));
  ap.appendChild(btn);
  ap.appendChild(el("p", "muted", "The button sends exactly the digest shown above. Before sending, the page fetches the review again and stops if anything changed."));
  panel.appendChild(ap);

  // Reject
  const rj = el("div", "reject-box");
  rj.appendChild(el("h2", null, "Reject"));
  const ta = el("textarea");
  ta.rows = 2;
  ta.maxLength = 500;
  ta.placeholder = "Reason (required, stored in the audit log)";
  ta.setAttribute("aria-label", "Reason for rejecting");
  rj.appendChild(ta);
  const rbtn = el("button", "btn danger", "Reject");
  rbtn.type = "button";
  rbtn.disabled = true;
  ta.addEventListener("input", () => {
    rbtn.disabled = ta.value.trim() === "";
  });
  rbtn.addEventListener("click", () => reject(rbtn, ta, status, s.id, seq));
  rj.appendChild(rbtn);
  panel.appendChild(rj);

  panel.appendChild(status);
  return panel;
}

async function approve(btn, cb, status, seq) {
  const shown = state.shown;
  if (!shown || seq !== state.seq) return;
  btn.disabled = true;
  cb.disabled = true;
  status.replaceChildren(el("p", "muted", "Checking that the proposal did not change..."));
  let fresh;
  try {
    fresh = await api("GET", "proposals/" + encodeURIComponent(shown.id) + "/review");
  } catch (e) {
    status.replaceChildren(errorBox(e));
    cb.disabled = false;
    return;
  }
  if (seq !== state.seq || state.shown !== shown) return;
  const fs = fresh.summary || {};
  const problems = [];
  if (fs.digest !== shown.digest) problems.push("the digest is different");
  if (fs.state !== "pending") problems.push("it is no longer pending (now " + fs.state + ")");
  if (fs.status === "stale") problems.push("it became stale (a touched file changed)");
  if (JSON.stringify(fresh) !== shown.snapshot) problems.push("the review is not identical to the one on screen");
  if (problems.length) {
    const box = el("div", "banner error");
    appendText(box, "Not approved: the proposal changed since this page loaded it: " + problems.join("; ") + ". Reload and read it again.");
    const reload = el("button", "btn small", "Reload review");
    reload.type = "button";
    reload.addEventListener("click", () => route());
    box.appendChild(reload);
    status.replaceChildren(box);
    return;
  }
  status.replaceChildren(el("p", "muted", "Approving..."));
  try {
    const res = await api("POST", "proposals/" + encodeURIComponent(shown.id) + "/approve", { digest: shown.digest });
    const ok = el("div", "banner ok");
    appendText(ok, "Approved. Commit " + res.commit + ".");
    status.replaceChildren(ok);
    state.shown = null;
    loadTree().catch(() => {});
    refreshCount();
  } catch (e) {
    status.replaceChildren(errorBox(e));
  }
}

async function reject(btn, ta, status, id, seq) {
  const reason = ta.value.trim();
  if (!reason || seq !== state.seq) return;
  if (!window.confirm("Reject proposal " + short(id) + "?")) return;
  btn.disabled = true;
  try {
    await api("POST", "proposals/" + encodeURIComponent(id) + "/reject", { reason });
    const ok = el("div", "banner ok");
    appendText(ok, "Rejected.");
    status.replaceChildren(ok);
    state.shown = null;
    refreshCount();
  } catch (e) {
    btn.disabled = false;
    status.replaceChildren(errorBox(e));
  }
}

async function refreshCount() {
  try {
    const st = await api("GET", "status");
    setPending(st.pending);
  } catch {
    // ignore
  }
}

// ---- wiring ----

function init() {
  $("login-btn").addEventListener("click", signIn);
  for (const id of ["owner-token", "password", "password-confirm"]) {
    $(id).addEventListener("keydown", (event) => {
      if (event.key === "Enter") { event.preventDefault(); signIn(); }
    });
  }
  $("lock").addEventListener("click", () => signOut());
  $("filter").addEventListener("input", renderTree);
  const doSearch = () => {
    const value = $("search").value.trim();
    if (value) location.hash = "#/search?" + q({ q: value });
  };
  $("search-btn").addEventListener("click", doSearch);
  $("search").addEventListener("keydown", (event) => { if (event.key === "Enter") doSearch(); });
  $("menu").addEventListener("click", () => {
    const open = document.body.classList.toggle("side-open");
    $("menu").setAttribute("aria-expanded", open ? "true" : "false");
  });
  for (const event of ["click", "keydown", "scroll", "touchstart"]) document.addEventListener(event, touch, { passive: true });
  window.addEventListener("hashchange", route);
  loadAuthState(true);
}

init();
