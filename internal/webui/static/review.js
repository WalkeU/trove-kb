// Trove UI: the changed-files area of a review.
//
// A change tree on the left (added, modified, deleted, with line counts and
// viewed marks) and every changed file stacked as a card on the right, in a
// unified or a side-by-side diff. Each card has a "Viewed" switch; the
// approve step requires every file to be marked viewed (onViewed). Only DOM
// construction through render.js helpers; text arrives already escaped.

import { el, appendText, appendEscaped } from "./render.js";
import { parseDiff, splitRows, pairChanges, inlineSpan, changeTree, treeOrder, fileStatus, STATUS_LETTER, language } from "./changes.js";

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

// Diff style shared by every card and kept while the page is open, so the
// next proposal opens the way the owner left the last one.
let diffStyle = "unified";

// renderChanges draws the change tree and every changed file as a card.
// opts.onViewed(n, total) reports how many files were marked viewed.
export function renderChanges(files, opts) {
  const viewed = new Set();
  const tree = changeTreeView(files, { onSelect: (i) => select(i) });
  const report = () => { tree.setViewed(viewed); opts.onViewed(viewed.size, files.length); };
  const root = el("div", "changes");
  root.appendChild(tree.node);
  if (files.length === 0) {
    root.appendChild(el("p", "muted", "This proposal changes no files."));
    report();
    return root;
  }

  const stream = el("section", "stream");
  root.appendChild(stream);

  const bar = el("div", "stream-bar");
  bar.appendChild(el("span", "stream-title", files.length + " changed file(s)"));
  const redraws = [];
  bar.appendChild(segmented("Diff style", [["unified", "Unified"], ["split", "Split"]], diffStyle, (v) => {
    diffStyle = v;
    for (const r of redraws) r();
  }).node);
  stream.appendChild(bar);

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
    // Split only helps when both sides exist: added and deleted files stay
    // in one column.
    const draw = () => {
      const rows = rowsFor(f, whole);
      if (diffStyle === "split" && fileStatus(f) === "modified") {
        const cols = el("div", "split-head");
        cols.appendChild(el("span", null, "Before"));
        cols.appendChild(el("span", null, "After"));
        body.replaceChildren(cols, splitCode(rows));
      } else {
        body.replaceChildren(unifiedCode(rows));
      }
    };
    draw();
    redraws.push(draw);
    card.appendChild(body);
    if (f.full_diff) {
      const more = el("button", "btn small expand", "Show the whole file");
      more.type = "button";
      more.addEventListener("click", () => {
        whole = !whole;
        more.textContent = whole ? "Show changes only" : "Show the whole file";
        draw();
      });
      card.appendChild(more);
    }

    const fold = (open) => {
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      card.classList.toggle("folded", !open);
    };
    toggle.addEventListener("click", () => fold(card.classList.contains("folded")));
    cb.addEventListener("change", () => {
      if (cb.checked) viewed.add(i); else viewed.delete(i);
      report();
      fold(!cb.checked);
      if (cb.checked) {
        const nextCard = cards.get(tree.order[tree.order.indexOf(i) + 1]);
        if (nextCard) nextCard.scrollIntoView({ block: "start", behavior: "smooth" });
      }
    });
    cards.set(i, card);
    stream.appendChild(card);
  }

  const select = (i) => {
    const c = cards.get(i);
    if (!c) return;
    c.classList.remove("folded");
    c.scrollIntoView({ block: "start", behavior: "smooth" });
    tree.setCurrent(i);
  };
  // The tree follows the card at the top of the screen.
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
