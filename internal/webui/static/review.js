// Trove UI: the changed-files area of a review, in three layouts.
//
//   a  Workspace: change tree on the left, one file at a time on the right
//      (unified diff with line numbers, changes only or the whole file).
//   b  Stream: change tree on the left, every file stacked as a card with a
//      "Viewed" switch; the tree follows the scroll position.
//   c  Split: change tree on the left, old and new side by side for one
//      file, changed spans highlighted, with a change map beside the code.
//
// Every layout reports which files the owner has opened (onViewed), so the
// approve step can require that every file was looked at. Only DOM
// construction through render.js helpers; text arrives already escaped.

import { el, appendText, appendEscaped } from "./render.js";
import { parseDiff, splitRows, pairChanges, inlineSpan, changeTree, treeOrder, fileStatus, STATUS_LETTER, language } from "./changes.js";

export const LAYOUTS = [
  ["a", "Workspace", "One file at a time, unified diff"],
  ["b", "Stream", "All files stacked, mark each as viewed"],
  ["c", "Split", "Old and new side by side"],
];

export function layoutOf(v) {
  return LAYOUTS.some(([k]) => k === v) ? v : "a";
}

const STATUS_WORD = { added: "added", modified: "modified", deleted: "deleted" };

function statusChip(status) {
  const s = el("span", "st st-" + status, STATUS_LETTER[status]);
  s.title = STATUS_WORD[status];
  return s;
}

function counts(plus, minus) {
  const wrap = el("span", "lc");
  if (plus) wrap.appendChild(el("span", "lc-add", "+" + plus));
  if (minus) wrap.appendChild(el("span", "lc-del", "−" + minus));
  if (!plus && !minus) wrap.appendChild(el("span", "muted", "0"));
  return wrap;
}

// ---- change tree ----

function changeTreeView(files, opts) {
  const tree = changeTree(files);
  const nav = el("nav", "ctree");
  nav.setAttribute("aria-label", "Changed files");
  const head = el("div", "ctree-head");
  head.appendChild(el("span", "ctree-title", "Changed files"));
  const prog = el("span", "ctree-prog");
  head.appendChild(prog);
  nav.appendChild(head);
  const items = new Map();
  const dirRow = (d, depth) => {
    const box = el("div", "ct-dir");
    const row = el("button", "ct-row ct-folder");
    row.type = "button";
    row.style.setProperty("--depth", String(depth));
    row.setAttribute("aria-expanded", "true");
    row.appendChild(el("span", "ct-caret", "▾"));
    row.appendChild(el("span", "ct-name", d.name + "/"));
    const sum = el("span", "ct-sum");
    for (const k of ["added", "modified", "deleted"]) {
      if (d.counts[k]) sum.appendChild(el("span", "ct-n st-" + k, String(d.counts[k])));
    }
    row.appendChild(sum);
    const kids = el("div", "ct-kids");
    row.addEventListener("click", () => {
      const open = row.getAttribute("aria-expanded") !== "true";
      row.setAttribute("aria-expanded", open ? "true" : "false");
      kids.hidden = !open;
    });
    box.appendChild(row);
    fill(kids, d, depth + 1);
    box.appendChild(kids);
    return box;
  };
  const fill = (parent, node, depth) => {
    for (const d of node.dirs) parent.appendChild(dirRow(d, depth));
    for (const f of node.files) {
      const b = el("button", "ct-row ct-file st-row-" + f.status);
      b.type = "button";
      b.style.setProperty("--depth", String(depth));
      b.title = f.path;
      b.appendChild(statusChip(f.status));
      b.appendChild(el("span", "ct-name", f.name));
      const d = parseDiff(files[f.index].diff);
      b.appendChild(counts(d.added, d.removed));
      b.appendChild(el("span", "ct-seen"));
      b.addEventListener("click", () => opts.onSelect(f.index));
      items.set(f.index, b);
      parent.appendChild(b);
    }
  };
  const list = el("div", "ctree-list");
  fill(list, tree, 0);
  nav.appendChild(list);
  const legend = el("div", "ctree-legend");
  for (const k of ["added", "modified", "deleted"]) {
    const l = el("span");
    l.appendChild(statusChip(k));
    appendText(l, " " + STATUS_WORD[k]);
    legend.appendChild(l);
  }
  nav.appendChild(legend);
  return {
    node: nav,
    order: treeOrder(tree),
    setCurrent(index) {
      for (const [i, b] of items) {
        if (i === index) b.setAttribute("aria-current", "true");
        else b.removeAttribute("aria-current");
      }
    },
    setViewed(viewed) {
      for (const [i, b] of items) b.classList.toggle("seen", viewed.has(i));
      prog.textContent = viewed.size + " / " + files.length + " viewed";
    },
  };
}

// ---- code rendering ----

function textCell(cls, text, span) {
  const c = el("span", cls);
  if (text === "") { appendText(c, " "); return c; }
  if (!span) return appendEscaped(c, text);
  if (span[0] > 0) appendEscaped(c, text.slice(0, span[0]));
  c.appendChild(appendEscaped(el("mark", "hl"), text.slice(span[0], span[1])));
  if (span[1] < text.length) appendEscaped(c, text.slice(span[1]));
  return c;
}

function gapRow(count) {
  const r = el("div", "cr cr-gap");
  appendText(r, "⋯ " + count + " unchanged line(s)");
  return r;
}

function noteRow(text) {
  const r = el("div", "cr cr-note");
  appendText(r, text);
  return r;
}

// unifiedCode: old no, new no, marker, text. Paired lines get their
// changed span highlighted.
function unifiedCode(rows) {
  const code = el("div", "code unified");
  code.setAttribute("role", "table");
  const partner = pairChanges(rows);
  for (const r of rows) {
    if (r.kind === "gap") { code.appendChild(gapRow(r.count)); continue; }
    if (r.kind === "note") { code.appendChild(noteRow(r.text)); continue; }
    const row = el("div", "cr cr-" + r.kind);
    row.appendChild(el("span", "cn", r.old ? String(r.old) : ""));
    row.appendChild(el("span", "cn", r.new ? String(r.new) : ""));
    row.appendChild(el("span", "cm", r.kind === "add" ? "+" : r.kind === "del" ? "−" : ""));
    const p = partner.get(r);
    row.appendChild(textCell("ct", r.text, p ? inlineSpan(r.text, p.text) : null));
    code.appendChild(row);
  }
  return code;
}

// splitCode: old no, old text | new no, new text.
function splitCode(rows) {
  const code = el("div", "code split");
  for (const p of splitRows(rows)) {
    if (p.gap !== undefined) { code.appendChild(gapRow(p.gap)); continue; }
    if (p.note !== undefined) { code.appendChild(noteRow(p.note)); continue; }
    const row = el("div", "cr sr" + (p.left === p.right ? " cr-ctx" : ""));
    const same = p.left === p.right;
    const lspan = !same && p.left && p.right ? inlineSpan(p.left.text, p.right.text) : null;
    const rspan = !same && p.left && p.right ? inlineSpan(p.right.text, p.left.text) : null;
    const side = (r, kind, span) => {
      const cls = !r ? " empty" : same ? "" : " " + kind;
      row.appendChild(el("span", "cn" + cls, r ? String(kind === "del" ? r.old : r.new) : ""));
      row.appendChild(r ? textCell("ct" + cls, r.text, span) : el("span", "ct" + cls));
    };
    side(p.left, "del", lspan);
    side(p.right, "add", rspan);
    code.appendChild(row);
  }
  return code;
}

function fileHead(f, d, extra) {
  const head = el("div", "fhead");
  const status = fileStatus(f);
  head.appendChild(statusChip(status));
  const path = el("span", "fpath");
  const cut = f.path.lastIndexOf("/");
  if (cut >= 0) path.appendChild(el("span", "fdir", f.path.slice(0, cut + 1)));
  appendText(path, f.path.slice(cut + 1));
  head.appendChild(path);
  head.appendChild(el("span", "fstate st-text-" + status, STATUS_WORD[status]));
  head.appendChild(el("span", "flang", language(f.path)));
  head.appendChild(counts(d.added, d.removed));
  if (extra) head.appendChild(extra);
  return head;
}

function segmented(label, options, current, onPick) {
  const g = el("div", "seg");
  g.setAttribute("role", "group");
  g.setAttribute("aria-label", label);
  const buttons = [];
  for (const [value, text] of options) {
    const b = el("button", "seg-btn", text);
    b.type = "button";
    b.setAttribute("aria-pressed", value === current ? "true" : "false");
    b.addEventListener("click", () => {
      for (const x of buttons) x.setAttribute("aria-pressed", x === b ? "true" : "false");
      onPick(value);
    });
    buttons.push(b);
    g.appendChild(b);
  }
  return { node: g, buttons };
}

// codeFor picks the rows for "changes only" or "whole file".
function rowsFor(f, whole) {
  return parseDiff(whole && f.full_diff ? f.full_diff : f.diff).rows;
}

// ---- layouts ----

export function renderChanges(files, opts) {
  const layout = layoutOf(opts.layout);
  const viewed = new Set();
  const tree = changeTreeView(files, { onSelect: (i) => select(i) });
  const report = () => { tree.setViewed(viewed); opts.onViewed(viewed.size, files.length); };
  const markViewed = (i, on = true) => {
    if (on) viewed.add(i); else viewed.delete(i);
    report();
  };
  const root = el("div", "changes layout-" + layout);
  root.appendChild(tree.node);
  let select = () => {};

  if (files.length === 0) {
    root.appendChild(el("p", "muted", "This proposal changes no files."));
    report();
    return root;
  }

  if (layout === "a" || layout === "c") {
    const pane = el("section", "pane");
    pane.setAttribute("aria-live", "polite");
    root.appendChild(pane);
    let current = tree.order[0];
    let whole = false;
    let split = layout === "c";
    const draw = () => {
      const f = files[current];
      const d = parseDiff(f.diff);
      const pos = tree.order.indexOf(current);
      const tools = el("div", "ftools");
      const mode = segmented("Lines shown", [["changes", "Changes"], ["whole", "Whole file"]], whole ? "whole" : "changes", (v) => { whole = v === "whole"; draw(); });
      if (!f.full_diff) { for (const b of mode.buttons) b.disabled = true; mode.node.title = "A deleted file has only its removed lines"; }
      tools.appendChild(mode.node);
      if (layout === "c") {
        tools.appendChild(segmented("Diff style", [["split", "Split"], ["unified", "Unified"]], split ? "split" : "unified", (v) => { split = v === "split"; draw(); }).node);
      }
      const nav = el("div", "fnav");
      const prev = el("button", "btn small", "← Previous");
      prev.type = "button";
      prev.disabled = pos <= 0;
      prev.addEventListener("click", () => select(tree.order[pos - 1]));
      const next = el("button", "btn small", "Next →");
      next.type = "button";
      next.disabled = pos >= tree.order.length - 1;
      next.addEventListener("click", () => select(tree.order[pos + 1]));
      nav.appendChild(el("span", "muted small", "File " + (pos + 1) + " of " + files.length));
      nav.appendChild(prev);
      nav.appendChild(next);
      tools.appendChild(nav);
      const rows = rowsFor(f, whole);
      const body = el("div", "fbody");
      // An added or deleted file has only one side: no empty half.
      const sideBySide = split && layout === "c" && fileStatus(f) === "modified";
      const code = sideBySide ? splitCode(rows) : unifiedCode(rows);
      if (sideBySide) {
        const cols = el("div", "split-head");
        cols.appendChild(el("span", null, fileStatus(f) === "added" ? "(new file)" : "Before"));
        cols.appendChild(el("span", null, fileStatus(f) === "deleted" ? "(deleted)" : "After"));
        body.appendChild(cols);
      }
      body.appendChild(code);
      const wrap = el("div", "fcard");
      wrap.appendChild(fileHead(f, d));
      wrap.appendChild(tools);
      if (layout === "c") {
        const frame = el("div", "frame");
        frame.appendChild(body);
        frame.appendChild(changeMap(code));
        wrap.appendChild(frame);
      } else {
        wrap.appendChild(body);
      }
      pane.replaceChildren(wrap);
    };
    select = (i) => {
      current = i;
      tree.setCurrent(i);
      markViewed(i);
      draw();
      pane.scrollIntoView({ block: "nearest" });
    };
    root.addEventListener("keydown", (event) => {
      if (event.target.closest && event.target.closest("textarea, input")) return;
      const pos = tree.order.indexOf(current);
      if ((event.key === "j" || event.key === "ArrowDown" && event.altKey) && pos < tree.order.length - 1) { event.preventDefault(); select(tree.order[pos + 1]); }
      if ((event.key === "k" || event.key === "ArrowUp" && event.altKey) && pos > 0) { event.preventDefault(); select(tree.order[pos - 1]); }
    });
    root.tabIndex = -1;
    tree.setCurrent(current);
    markViewed(current);
    draw();
    return root;
  }

  // layout b: stream of cards
  const stream = el("section", "stream");
  root.appendChild(stream);
  const cards = new Map();
  for (const i of tree.order) {
    const f = files[i];
    const d = parseDiff(f.diff);
    const card = el("article", "fcard scard");
    card.dataset.index = String(i);
    const toggle = el("button", "icon-btn fold", "▾");
    toggle.type = "button";
    toggle.setAttribute("aria-label", "Collapse " + f.path);
    toggle.setAttribute("aria-expanded", "true");
    const seen = el("label", "seen-toggle");
    const cb = el("input");
    cb.type = "checkbox";
    seen.appendChild(cb);
    appendText(seen, " Viewed");
    const head = fileHead(f, d, seen);
    head.insertBefore(toggle, head.firstChild);
    card.appendChild(head);
    let whole = false;
    const body = el("div", "fbody");
    const draw = () => body.replaceChildren(unifiedCode(rowsFor(f, whole)));
    draw();
    if (f.full_diff) {
      const more = el("button", "btn small expand", "Show the whole file");
      more.type = "button";
      more.addEventListener("click", () => {
        whole = !whole;
        more.textContent = whole ? "Show changes only" : "Show the whole file";
        draw();
      });
      card.appendChild(body);
      card.appendChild(more);
    } else {
      card.appendChild(body);
    }
    const fold = (open) => {
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      card.classList.toggle("folded", !open);
    };
    toggle.addEventListener("click", () => fold(card.classList.contains("folded")));
    cb.addEventListener("change", () => {
      markViewed(i, cb.checked);
      fold(!cb.checked);
      if (cb.checked) {
        const at = tree.order.indexOf(i);
        const nextCard = cards.get(tree.order[at + 1]);
        if (nextCard) nextCard.scrollIntoView({ block: "start", behavior: "smooth" });
      }
    });
    cards.set(i, card);
    stream.appendChild(card);
  }
  select = (i) => {
    const c = cards.get(i);
    if (!c) return;
    c.classList.remove("folded");
    c.scrollIntoView({ block: "start", behavior: "smooth" });
    tree.setCurrent(i);
  };
  if (typeof IntersectionObserver === "function") {
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) tree.setCurrent(Number(e.target.dataset.index));
    }, { rootMargin: "-20% 0px -70% 0px" });
    for (const c of cards.values()) io.observe(c);
  }
  tree.setCurrent(tree.order[0]);
  report();
  return root;
}

// changeMap draws a thin strip beside the code with a mark for every run
// of changed lines; clicking a mark scrolls the code to it.
function changeMap(code) {
  const map = el("div", "cmap");
  map.setAttribute("aria-hidden", "true");
  const rows = [...code.childNodes];
  const n = rows.length || 1;
  let prev = false;
  rows.forEach((r, k) => {
    const changed = /\bcr-(add|del)\b/.test(r.className) || (r.querySelector && r.querySelector(".ct.add, .ct.del"));
    if (changed && !prev) {
      const m = el("span", "cmap-mark");
      m.style.setProperty("--at", (k / n * 100).toFixed(2) + "%");
      m.addEventListener("click", () => r.scrollIntoView({ block: "center", behavior: "smooth" }));
      map.appendChild(m);
    }
    prev = !!changed;
  });
  return map;
}
