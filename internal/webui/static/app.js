// Trove browser UI. Authentication credentials live only in HttpOnly
// cookies managed by the server. JavaScript reads a separate CSRF value,
// never the access token, refresh token or password after submission.

import { parse, filterPaths, parseChangelog } from "./md.js";
import { el, appendText, renderBlocks, readHref } from "./render.js";
import { renderChanges } from "./review.js";
import { summarize } from "./changes.js";

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
  about: null,
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
  $("version").hidden = true;
  state.about = null;
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
  $("nav-settings").hidden = status.role !== "approver";
  $("nav-history").hidden = status.role !== "approver";
  setPending(status.pending);
  loadAbout();
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
  $("nav-read").classList.toggle("active", !["review", "account", "settings", "history", "about"].includes(segs[0]));
  $("nav-settings").classList.toggle("active", segs[0] === "settings");
  $("nav-history").classList.toggle("active", segs[0] === "history");
  $("nav-about").classList.toggle("active", segs[0] === "about");
  $("nav-account").classList.toggle("active", segs[0] === "account");
  $("nav-review").classList.toggle("active", segs[0] === "review");
  // A single review uses the whole width: the change tree replaces the
  // knowledge base tree while it is open.
  $("app").classList.toggle("wide", segs[0] === "review" && !!segs[1] && state.role === "approver");
  markCurrent();
  try {
    if (segs[0] === "read" && segs.length > 1) {
      await showFile(seq, segs.slice(1).join("/"), query.get("view") === "source");
    } else if (segs[0] === "search") {
      await showSearch(seq, query.get("q") || "");
    } else if (segs[0] === "account") {
      showAccount();
    } else if (segs[0] === "about") {
      await showAbout(seq);
    } else if (segs[0] === "history" && state.role === "approver") {
      await showHistory(seq, query.get("kind") || "all");
    } else if (segs[0] === "settings" && state.role === "approver") {
      await showSettings(seq);
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

const lines = (text) => text.split("\n").map((l) => l.trim()).filter(Boolean);

async function showSettings(seq, notice) {
  const cur = await api("GET", "settings");
  if (seq !== state.seq) return;
  const box = el("div", "account settings");
  box.appendChild(el("h1", null, "Settings"));
  box.appendChild(el("p", "muted", "Rules for what proposals may touch. Saved on the server (data_dir/settings.json) and applied at once, no restart. Before saving, the change is checked against the existing files and the open proposals."));
  const field = (label, hint, input) => {
    const row = el("label", "account-field", label);
    row.appendChild(input);
    row.appendChild(el("span", "muted small", hint));
    box.appendChild(row);
    return input;
  };
  const area = (values) => {
    const ta = el("textarea");
    ta.rows = Math.max(4, values.length + 1);
    ta.spellcheck = false;
    ta.autocapitalize = "off";
    ta.value = values.join("\n");
    return ta;
  };
  const dirs = field("Allowed folders (top level, one per line)", "Agents can write only inside these folders. To rename a folder, add the new name and keep the old one until its files are moved.", area(cur.allowed_dirs));
  const exts = field("Allowed file extensions (one per line)", "Lowercase with a dot, for example .md, .yml, .tf. Frontmatter is required for .md only. Every type is scanned for secrets.", area(cur.allowed_extensions));
  const max = el("input");
  max.type = "number";
  max.min = "1";
  max.max = "500";
  max.step = "1";
  max.value = String(cur.max_files);
  field("Max files per proposal (1 to 500)", "Larger proposals are refused when an agent submits them.", max);

  const message = el("div");
  if (notice) message.appendChild(el("div", "banner ok", notice));
  const actions = el("div", "settings-actions");
  const save = el("button", "btn primary", "Save settings");
  save.type = "button";
  actions.appendChild(save);
  box.appendChild(actions);
  box.appendChild(message);
  renameSection(box, message);

  const body = () => ({ allowed_dirs: lines(dirs.value), allowed_extensions: lines(exts.value), max_files: Number(max.value) });
  const show = (res) => {
    dirs.value = res.allowed_dirs.join("\n");
    exts.value = res.allowed_extensions.join("\n");
    max.value = String(res.max_files);
  };
  const doSave = async () => {
    save.disabled = true;
    message.replaceChildren();
    try {
      const res = await api("PUT", "settings", body());
      show(res);
      message.appendChild(el("div", "banner ok", "Saved and applied."));
    } catch (error) { message.replaceChildren(errorBox(error)); }
    finally { save.disabled = false; }
  };
  save.addEventListener("click", async () => {
    message.replaceChildren();
    const n = Number(max.value);
    if (max.value.trim() === "" || !Number.isInteger(n) || n < 1 || n > 500) {
      message.appendChild(errorBox(new Error("Max files per proposal must be a whole number from 1 to 500.")));
      return;
    }
    save.disabled = true;
    try {
      const check = await api("PUT", "settings?dry_run=1", body());
      if (!check.warnings || check.warnings.length === 0) { save.disabled = false; await doSave(); return; }
      const warn = el("div", "banner warn");
      warn.appendChild(el("strong", null, "This change conflicts with existing content:"));
      const ul = el("ul");
      for (const w of check.warnings) ul.appendChild(el("li", null, w));
      warn.appendChild(ul);
      const row = el("div", "settings-actions");
      const go = el("button", "btn danger", "Save anyway");
      go.type = "button";
      go.addEventListener("click", async () => { go.disabled = true; cancel.disabled = true; await doSave(); });
      const cancel = el("button", "btn", "Cancel");
      cancel.type = "button";
      cancel.addEventListener("click", () => message.replaceChildren());
      row.appendChild(go);
      row.appendChild(cancel);
      warn.appendChild(row);
      message.replaceChildren(warn);
    } catch (error) { message.replaceChildren(errorBox(error)); }
    finally { save.disabled = false; }
  });
  setView(box);
}

function renameSection(box, notice) {
  box.appendChild(el("h2", null, "Rename a folder"));
  box.appendChild(el("p", "muted", "Moves every file of a top-level folder to the new name in one commit and updates the allowed folders. It merges into nothing: the new name must not exist. Links inside notes are not rewritten."));
  const folders = [...new Set(state.files.filter((f) => f.includes("/")).map((f) => f.split("/")[0]))].sort();
  const sel = el("select");
  for (const f of folders) { const o = el("option", null, f); o.value = f; sel.appendChild(o); }
  const fromRow = el("label", "account-field", "Folder to rename");
  fromRow.appendChild(sel);
  box.appendChild(fromRow);
  const to = el("input");
  to.type = "text";
  to.spellcheck = false;
  to.autocapitalize = "off";
  const toRow = el("label", "account-field", "New name");
  toRow.appendChild(to);
  box.appendChild(toRow);
  const out = el("div");
  const check = el("button", "btn", "Check rename");
  check.type = "button";
  const row = el("div", "settings-actions");
  row.appendChild(check);
  box.appendChild(row);
  box.appendChild(out);
  const payload = () => ({ from: sel.value, to: to.value.trim() });
  check.addEventListener("click", async () => {
    out.replaceChildren();
    notice.replaceChildren();
    if (!payload().to) { out.appendChild(errorBox(new Error("Enter the new folder name."))); return; }
    check.disabled = true;
    try {
      const r = await api("POST", "folders/rename?dry_run=1", payload());
      const b = el("div", r.warnings && r.warnings.length ? "banner warn" : "banner");
      b.appendChild(el("strong", null, r.files + " file(s) will move from " + r.from + "/ to " + r.to + "/."));
      if (r.warnings && r.warnings.length) {
        const ul = el("ul");
        for (const w of r.warnings) ul.appendChild(el("li", null, w));
        b.appendChild(ul);
      }
      const act = el("div", "settings-actions");
      const go = el("button", "btn danger", "Rename now");
      go.type = "button";
      const cancel = el("button", "btn", "Cancel");
      cancel.type = "button";
      cancel.addEventListener("click", () => out.replaceChildren());
      go.addEventListener("click", async () => {
        go.disabled = true;
        cancel.disabled = true;
        try {
          const done = await api("POST", "folders/rename", payload());
          await loadTree();
          await showSettings(state.seq, "Renamed " + done.from + "/ to " + done.to + "/ (" + done.files + " file(s), commit " + short(done.commit) + "). The allowed folders were updated.");
        } catch (error) { out.replaceChildren(errorBox(error)); }
      });
      act.appendChild(go);
      act.appendChild(cancel);
      b.appendChild(act);
      out.replaceChildren(b);
    } catch (error) { out.replaceChildren(errorBox(error)); }
    finally { check.disabled = false; }
  });
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


// ---- about: version and changelog ----

async function loadAbout() {
  try {
    const a = await api("GET", "about");
    state.about = a;
    const v = $("version");
    v.textContent = a.version ? "v" + String(a.version) : "";
    v.hidden = !a.version;
  } catch { /* the version label is optional */ }
}

// inlineCode renders `code` spans, everything else as plain text.
function inlineCode(parent, s) {
  for (const part of String(s).split(/(`[^`]+`)/)) {
    if (/^`[^`]+`$/.test(part)) parent.appendChild(el("code", null, part.slice(1, -1)));
    else if (part) appendText(parent, part);
  }
}

async function showAbout(seq) {
  const a = state.about || await api("GET", "about");
  if (seq !== state.seq) return;
  state.about = a;
  const version = String(a.version || "");
  const box = el("div", "about");
  box.appendChild(el("h1", null, "About Trove"));
  const p = el("p", "version-line");
  appendText(p, "Running version ");
  p.appendChild(el("strong", null, version ? "v" + version : "unknown"));
  box.appendChild(p);
  box.appendChild(el("h2", null, "Changelog"));
  const groups = parseChangelog(a.changelog);
  if (!groups.length) box.appendChild(el("p", "muted", "The changelog is empty."));
  for (const g of groups) {
    const sec = el("section", "release");
    const h = el("h3");
    if (g.version) {
      appendText(h, "v" + g.version);
      if (g.date) h.appendChild(el("span", "muted release-date", g.date));
      if (g.version === version) h.appendChild(el("span", "badge ready", "running"));
    } else {
      appendText(h, "Unreleased");
      h.appendChild(el("span", "badge", "not in a release yet"));
    }
    sec.appendChild(h);
    if (!g.entries.length) {
      sec.appendChild(el("p", "muted", "No entries."));
    } else {
      const ul = el("ul", "changes");
      for (const e of g.entries) {
        const li = el("li");
        li.appendChild(el("span", "muted change-date", e.date));
        inlineCode(li, e.text);
        ul.appendChild(li);
      }
      sec.appendChild(ul);
    }
    box.appendChild(sec);
  }
  setView(box);
}

// ---- history of decisions ----

const historyKinds = [
  ["all", "All", "#/history"],
  ["applied", "Approved", "#/history?kind=applied"],
  ["rejected", "Rejected", "#/history?kind=rejected"],
  ["owner", "Owner actions", "#/history?kind=owner"],
];

// historyHref returns one of the fixed filter routes above.
function historyHref(kind) {
  const row = historyKinds.find(([k]) => k === kind);
  return row ? row[2] : "#/history";
}
const kindLabel = { applied: "approved", rejected: "rejected", import: "import", rename: "rename", bootstrap: "setup", other: "commit" };
const opLabel = { added: "added", modified: "changed", deleted: "deleted", write: "write" };

function historyMatches(kind, en) {
  if (kind === "all") return true;
  if (kind === "owner") return en.kind !== "applied" && en.kind !== "rejected";
  return en.kind === kind;
}

async function showHistory(seq, kind) {
  if (!historyKinds.some(([k]) => k === kind)) kind = "all";
  const res = await api("GET", "history");
  if (seq !== state.seq) return;
  const all = Array.isArray(res.entries) ? res.entries : [];
  const list = all.filter((en) => historyMatches(kind, en));
  const wrap = el("div", "history");
  wrap.appendChild(el("h1", null, "History"));
  wrap.appendChild(el("p", "muted", "What you approved and rejected, and the owner actions (import, folder renames), newest first. Approved changes are read from the knowledge base history, so they never drop out."));
  const tabs = el("nav", "tabs");
  tabs.setAttribute("aria-label", "Filter history");
  for (const [k, label] of historyKinds) {
    const n = all.filter((en) => historyMatches(k, en)).length;
    const t = el("a", k === kind ? "tab active" : "tab", label + " (" + n + ")");
    t.href = historyHref(k);
    if (k === kind) t.setAttribute("aria-current", "page");
    tabs.appendChild(t);
  }
  wrap.appendChild(tabs);
  if (res.truncated) wrap.appendChild(el("p", "muted", "Only the newest " + all.length + " entries are shown."));
  if (!list.length) wrap.appendChild(el("p", "muted", "Nothing here yet."));
  for (const en of list) {
    const card = el("div", "card history-item");
    const top = el("div", "card-top");
    const badge = en.kind === "applied" ? "badge ready" : en.kind === "rejected" ? "badge stale" : "badge";
    top.appendChild(el("span", badge, kindLabel[en.kind] || String(en.kind)));
    top.appendChild(el("span", "topic", String(en.topic || "")));
    card.appendChild(top);
    const meta = [fmtTime(en.time)];
    if (en.agent) meta.push("from " + en.agent);
    if (en.decided_by) {
      const verb = en.kind === "rejected" ? "rejected by " : en.kind === "applied" ? "approved by " : "by ";
      meta.push(verb + en.decided_by);
    }
    if (en.proposal) meta.push("proposal " + short(en.proposal));
    if (en.commit) meta.push("commit " + short(en.commit));
    card.appendChild(el("div", "card-meta muted", meta.filter(Boolean).join(" · ")));
    if (en.reason) card.appendChild(el("div", "card-flags", "Reason: " + String(en.reason)));
    const files = Array.isArray(en.files) ? en.files : [];
    if (files.length) {
      const det = el("details", "history-files");
      det.appendChild(el("summary", null, files.length + " file(s)"));
      const ul = el("ul", "flat");
      for (const f of files) {
        const li = el("li");
        li.appendChild(el("span", "op op-" + String(f.op), opLabel[f.op] || String(f.op)));
        const path = String(f.path);
        if (f.op !== "deleted" && en.kind !== "rejected" && state.fileSet.has(path)) li.appendChild(fileLink(path, path));
        else li.appendChild(el("span", "path", path));
        ul.appendChild(li);
      }
      det.appendChild(ul);
      card.appendChild(det);
    }
    wrap.appendChild(card);
  }
  setView(wrap);
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

async function showReview(seq, id) {
  const rv = await api("GET", "proposals/" + encodeURIComponent(id) + "/review");
  if (seq !== state.seq) return;
  renderReview(rv, seq);
}

function chip(label, value) {
  const c = el("span", "chip");
  c.appendChild(el("span", "chip-k", label));
  if (value instanceof Node) c.appendChild(value);
  else c.appendChild(el("span", "chip-v", String(value)));
  return c;
}

// statBar shows the share of added, modified and deleted files.
function statBar(sum, total) {
  const bar = el("div", "statbar");
  bar.setAttribute("aria-hidden", "true");
  for (const k of ["added", "modified", "deleted"]) {
    if (!sum[k]) continue;
    const seg = el("span", "statbar-" + k);
    seg.style.setProperty("--w", (sum[k] / total * 100).toFixed(2) + "%");
    bar.appendChild(seg);
  }
  return bar;
}

function renderReview(rv, seq) {
  const s = rv.summary;
  const snapshot = JSON.stringify(rv);
  state.shown = { id: s.id, digest: s.digest, snapshot };
  const files = rv.files || [];
  const sum = summarize(files);
  const wrap = el("div", "review");

  const top = el("div", "rv-top");
  const back = el("a", "back", "← All pending proposals");
  back.href = "#/review";
  top.appendChild(back);
  wrap.appendChild(top);

  const head = el("header", "rv-head");
  const title = el("div", "rv-title");
  title.appendChild(statusBadge(s));
  const h = el("h1", "topic");
  appendText(h, s.topic);
  title.appendChild(h);
  head.appendChild(title);
  const chips = el("div", "chips");
  chips.appendChild(chip("agent", s.agent));
  chips.appendChild(chip("proposal", short(s.id)));
  chips.appendChild(chip("base", short(s.base)));
  chips.appendChild(chip("submitted", fmtTime(s.submitted_at)));
  if (fmtTime(s.expires_at)) chips.appendChild(chip("expires", fmtTime(s.expires_at)));
  if ((s.scope || []).length) chips.appendChild(chip("scope", s.scope.join(", ")));
  if (s.supersedes) chips.appendChild(chip("supersedes", short(s.supersedes) + " (earlier reviews do not carry over)"));
  head.appendChild(chips);

  const stats = el("div", "rv-stats");
  const nums = el("div", "rv-nums");
  nums.appendChild(el("span", "rv-files", files.length + " file(s)"));
  for (const k of ["added", "modified", "deleted"]) {
    if (sum[k]) nums.appendChild(el("span", "rv-n st-text-" + k, sum[k] + " " + k));
  }
  const lines = el("span", "lc");
  lines.appendChild(el("span", "lc-add", "+" + sum.plus));
  lines.appendChild(el("span", "lc-del", "−" + sum.minus));
  nums.appendChild(lines);
  stats.appendChild(nums);
  if (files.length) stats.appendChild(statBar(sum, files.length));
  head.appendChild(stats);
  wrap.appendChild(head);

  wrap.appendChild(el("p", "untrusted", rv.notice));

  const alerts = el("div", "alerts");
  for (const f of s.stale_files || []) alerts.appendChild(el("div", "banner error", "STALE: " + f + " changed or moved since the proposal was made (for example its folder was renamed)"));
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

  // The cards report how many files were marked viewed; the approve box listens.
  const viewed = { n: 0, total: files.length, listeners: [] };
  wrap.appendChild(renderChanges(files, {
    onViewed(n, total) {
      viewed.n = n;
      viewed.total = total;
      for (const f of viewed.listeners) f();
    },
  }));

  const dg = el("div", "digest");
  dg.appendChild(el("div", "fm-label", "digest"));
  dg.appendChild(el("code", "digest-value", s.digest));
  wrap.appendChild(dg);

  if (s.state === "pending") wrap.appendChild(decisionPanel(s, seq, viewed));
  setView(wrap);
}

function decisionPanel(s, seq, viewed) {
  const panel = el("div", "decide");
  const status = el("div", "decide-status", "");
  status.setAttribute("role", "status");

  // Approve
  const ap = el("div", "approve-box");
  ap.appendChild(el("h2", null, "Approve"));
  if (s.status === "stale") {
    ap.appendChild(el("p", "banner error", "This proposal is stale (a touched file changed, or its folder was renamed or moved, since the proposal was made). It cannot be approved; the agent has to rebase it or submit it again in the current folder layout."));
  }
  // Every changed file must be marked viewed before the read-confirmation
  // can be ticked; the progress line says how many are left.
  const progress = el("p", "view-progress");
  ap.appendChild(progress);
  const lbl = el("label", "check");
  const cb = el("input");
  cb.type = "checkbox";
  lbl.appendChild(cb);
  appendText(lbl, " I have read the complete diff of every file.");
  ap.appendChild(lbl);
  const btn = el("button", "btn primary", "Approve digest " + short(s.digest));
  btn.type = "button";
  btn.disabled = true;
  const sync = () => {
    const done = viewed.n >= viewed.total;
    progress.replaceChildren();
    progress.classList.toggle("done", done);
    appendText(progress, done
      ? "All " + viewed.total + " file(s) marked viewed."
      : viewed.n + " of " + viewed.total + " file(s) marked viewed. Mark every file as viewed before approving.");
    cb.disabled = !done;
    if (!done) cb.checked = false;
    btn.disabled = !cb.checked || !done || s.status === "stale";
  };
  viewed.listeners.push(sync);
  sync();
  cb.addEventListener("change", sync);
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
  if (fs.status === "stale") problems.push("it became stale (a touched file changed or its folder was renamed)");
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
