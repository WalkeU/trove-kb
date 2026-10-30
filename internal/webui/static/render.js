// Trove UI: turns parsed markdown (md.js) into DOM nodes.
//
// Only createElement, createTextNode, textContent and a fixed set of
// attributes are used. No innerHTML, no attribute copied from content,
// no images, no frames. Links are built here and only here:
// internal ones point to "#/read/<path>", external ones must pass
// safeExternal (http or https) and open with rel="noopener noreferrer".

import { splitInvisible, escapeCodePoint, resolveHref, resolveWiki, ESCAPED } from "./md.js";

export function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) appendText(n, String(text));
  return n;
}

// appendText adds untrusted text; invisible characters become visible
// marks ("\u{200b}") instead of being rendered or dropped.
export function appendText(parent, s) {
  for (const part of splitInvisible(s)) {
    if (part.t === "text") {
      parent.appendChild(document.createTextNode(part.s));
    } else if (part.cp === BOM_CP) {
      parent.appendChild(bomMark());
    } else {
      const m = document.createElement("span");
      m.className = "inv";
      m.title = "invisible character U+" + part.cp.toString(16).toUpperCase().padStart(4, "0");
      m.textContent = escapeCodePoint(part.cp);
      parent.appendChild(m);
    }
  }
  return parent;
}

// U+FEFF, the byte order mark. Windows editors write it at the start of a
// file; it ends up in the middle when frontmatter is prepended to such a
// file. It gets a spelled-out label: a bare "BOM" glued to the next word
// (for example "BOMUSPRIV") reads like part of the text.
const BOM_CP = 0xfeff;

export function bomMark() {
  const m = el("span", "inv bom", "[hidden BOM character]");
  m.title = "Byte order mark (U+FEFF): an invisible character that some Windows editors put at the start of a file. "
    + "It has no meaning in a note and is removed when a proposal is submitted.";
  return m;
}

// appendEscaped is appendText plus highlighting of the server's own
// \u{....} escapes (review diffs arrive already escaped).
export function appendEscaped(parent, s) {
  let last = 0;
  for (const m of String(s).matchAll(ESCAPED)) {
    if (m.index > last) appendText(parent, s.slice(last, m.index));
    let mark;
    if (parseInt(m[0].slice(3, -1), 16) === BOM_CP) {
      mark = bomMark();
    } else {
      mark = el("span", "inv", m[0]);
      mark.title = "escaped invisible or control character";
    }
    parent.appendChild(mark);
    last = m.index + m[0].length;
  }
  if (last < s.length) appendText(parent, s.slice(last));
  return parent;
}

export function readHref(path) {
  return "#/read/" + path.split("/").map(encodeURIComponent).join("/");
}

function linkNode(res, children, ctx) {
  if (res.kind === "internal") {
    const a = el("a", "internal");
    a.href = readHref(res.path);
    a.title = res.path;
    for (const c of children) a.appendChild(c);
    return a;
  }
  if (res.kind === "external") {
    const a = el("a", "external");
    a.href = res.url;
    a.rel = "noopener noreferrer nofollow";
    a.target = "_blank";
    a.referrerPolicy = "no-referrer";
    a.title = res.url;
    for (const c of children) a.appendChild(c);
    return a;
  }
  const span = el("span", res.kind === "missing" ? "broken" : "nolink");
  if (res.kind === "missing") span.title = "not found in the knowledge base: " + res.target;
  for (const c of children) span.appendChild(c);
  return span;
}

function inlineNodes(nodes, ctx) {
  const out = [];
  for (const n of nodes) {
    switch (n.t) {
      case "text":
        out.push(appendText(document.createDocumentFragment(), n.s));
        break;
      case "br":
        out.push(document.createElement("br"));
        break;
      case "code":
        out.push(el("code", null, n.s));
        break;
      case "strong":
      case "em":
      case "del": {
        const e = el(n.t);
        for (const c of inlineNodes(n.c, ctx)) e.appendChild(c);
        out.push(e);
        break;
      }
      case "link":
        out.push(linkNode(resolveHref(n.href, ctx.current, ctx.files), inlineNodes(n.c, ctx), ctx));
        break;
      case "wiki": {
        const label = appendText(document.createDocumentFragment(), n.label);
        out.push(linkNode(resolveWiki(n.target, ctx.current, ctx.files), [label], ctx));
        break;
      }
      case "img":
        // Images from content are never loaded: show a text placeholder.
        out.push(el("span", "img-placeholder", "[image: " + (n.alt || "no description") + "]"));
        break;
    }
  }
  return out;
}

function fill(parent, nodes, ctx) {
  for (const c of inlineNodes(nodes, ctx)) parent.appendChild(c);
  return parent;
}

// renderBlocks appends the blocks to parent. ctx: {files: Set, current: path}.
export function renderBlocks(parent, blocks, ctx) {
  for (const b of blocks) {
    switch (b.t) {
      case "fm": {
        const box = el("div", "frontmatter");
        box.appendChild(el("div", "fm-label", "frontmatter"));
        const pre = el("pre");
        appendText(pre, b.lines.join("\n"));
        box.appendChild(pre);
        parent.appendChild(box);
        break;
      }
      case "h":
        parent.appendChild(fill(el("h" + Math.min(6, Math.max(1, b.level))), b.c, ctx));
        break;
      case "p":
        parent.appendChild(fill(el("p"), b.c, ctx));
        break;
      case "hr":
        parent.appendChild(el("hr"));
        break;
      case "code": {
        const pre = el("pre", "code");
        const code = el("code");
        appendText(code, b.s);
        pre.appendChild(code);
        parent.appendChild(pre);
        break;
      }
      case "quote":
        renderBlocks(parent.appendChild(el("blockquote")), b.c, ctx);
        break;
      case "list": {
        const list = el(b.ordered ? "ol" : "ul");
        for (const it of b.items) {
          const li = el("li");
          if (it.task !== null) {
            li.className = "task";
            li.appendChild(el("span", "check", it.task ? "[x] " : "[ ] "));
          }
          fill(li, it.c, ctx);
          if (it.sub.length) renderBlocks(li, it.sub, ctx);
          list.appendChild(li);
        }
        parent.appendChild(list);
        break;
      }
      case "table": {
        const wrap = el("div", "table-wrap");
        const table = el("table");
        const thead = el("thead");
        const tr = el("tr");
        for (const c of b.head) tr.appendChild(fill(el("th"), c, ctx));
        thead.appendChild(tr);
        table.appendChild(thead);
        const tbody = el("tbody");
        for (const row of b.rows) {
          const r = el("tr");
          for (const c of row) r.appendChild(fill(el("td"), c, ctx));
          tbody.appendChild(r);
        }
        table.appendChild(tbody);
        wrap.appendChild(table);
        parent.appendChild(wrap);
        break;
      }
    }
  }
  return parent;
}
