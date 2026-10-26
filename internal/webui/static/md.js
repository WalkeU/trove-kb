// Trove UI: markdown parser and link rules. Pure functions, no DOM.
//
// The knowledge base is written by agents, so every input here is
// untrusted. The parser never produces HTML: it returns a small tree of
// plain objects that render.js turns into DOM nodes with textContent
// only. Raw HTML in the markdown stays literal text.

const MAX_DEPTH = 8;

// ---- invisible characters ----

// Mirrors safe.IsInvisible on the server: control, format (zero width,
// bidi, tag characters), private use, unassigned, line and paragraph
// separators, non-ASCII spaces, variation selectors, CGJ, Hangul fillers.
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}\u034F\u115F\u1160\u17B4\u17B5\u180B-\u180F\u3164\uFE00-\uFE0F\uFFA0\u{E0100}-\u{E01EF}]/u;

export function isInvisible(ch) {
  if (ch === " " || ch === "\n" || ch === "\t") return false;
  return INVISIBLE.test(ch);
}

export function escapeCodePoint(cp) {
  return "\\u{" + cp.toString(16).padStart(4, "0") + "}";
}

// splitInvisible cuts s into visible text runs and single invisible code
// points: [{t:"text", s}, {t:"inv", cp}]. Lone surrogates come out as
// invisible (U+D800-DFFF are Cs, which the regex does not cover).
export function splitInvisible(s) {
  const out = [];
  let run = "";
  for (const ch of String(s)) {
    const cp = ch.codePointAt(0);
    if (isInvisible(ch) || (cp >= 0xd800 && cp <= 0xdfff)) {
      if (run) out.push({ t: "text", s: run });
      run = "";
      out.push({ t: "inv", cp });
    } else {
      run += ch;
    }
  }
  if (run) out.push({ t: "text", s: run });
  return out;
}

// ---- links ----

const SCHEME = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;

// safeExternal returns a normalized http(s) URL or "" for anything else
// (javascript:, data:, vbscript:, file:, protocol relative, whitespace or
// control characters inside the URL, unparsable values).
export function safeExternal(raw) {
  if (typeof raw !== "string" || raw.length > 2048) return "";
  for (const ch of raw) {
    // The URL parser silently drops tabs and newlines; refuse them instead.
    if (/\s/u.test(ch) || isInvisible(ch)) return "";
  }
  if (!/^https?:\/\//i.test(raw)) return "";
  let u;
  try {
    u = new URL(raw);
  } catch {
    return "";
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return "";
  if (!u.hostname) return "";
  return u.href;
}

function dirOf(path) {
  const i = path.lastIndexOf("/");
  return i < 0 ? "" : path.slice(0, i);
}

// joinPath resolves rel against dir. Returns "" if it climbs above the root.
export function joinPath(dir, rel) {
  const parts = rel.startsWith("/") ? [] : dir ? dir.split("/") : [];
  for (const seg of rel.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (parts.length === 0) return "";
      parts.pop();
      continue;
    }
    parts.push(seg);
  }
  return parts.join("/");
}

function lookup(files, p) {
  if (!p) return "";
  if (files.has(p)) return p;
  if (!/\.md$/i.test(p) && files.has(p + ".md")) return p + ".md";
  return "";
}

// resolveHref decides what a markdown link target becomes:
// {kind:"internal", path} for a file of the knowledge base,
// {kind:"external", url} for an http(s) URL,
// {kind:"missing", target} for a relative link to a file that does not exist,
// {kind:"none"} for everything else (other schemes, anchors, junk).
export function resolveHref(raw, current, files) {
  if (typeof raw !== "string") return { kind: "none" };
  const href = raw.trim();
  if (href === "" || href.startsWith("#") || href.startsWith("//") || href.startsWith("\\")) return { kind: "none" };
  if (SCHEME.test(href)) {
    const url = safeExternal(href);
    return url ? { kind: "external", url } : { kind: "none" };
  }
  let p = href.split("#")[0].split("?")[0];
  try {
    p = decodeURIComponent(p);
  } catch {
    return { kind: "none" };
  }
  for (const ch of p) {
    if (isInvisible(ch)) return { kind: "none" };
  }
  const target = joinPath(dirOf(current || ""), p);
  if (!target) return { kind: "none" };
  const found = lookup(files, target);
  return found ? { kind: "internal", path: found } : { kind: "missing", target };
}

// resolveWiki resolves [[target]]: a path relative to the current folder,
// a path from the root, or a unique-enough file name (case-insensitive,
// with or without .md). Ambiguous names pick the first in sorted order.
export function resolveWiki(target, current, files) {
  let t = String(target).split("#")[0].trim();
  if (!t) return { kind: "none" };
  for (const ch of t) {
    if (isInvisible(ch)) return { kind: "none" };
  }
  const rel = joinPath(dirOf(current || ""), t);
  let found = lookup(files, rel) || lookup(files, joinPath("", t));
  if (found) return { kind: "internal", path: found };
  const want = t.toLowerCase().replace(/\.md$/, "");
  const hits = [];
  for (const f of files) {
    const base = f.slice(f.lastIndexOf("/") + 1).toLowerCase().replace(/\.md$/, "");
    if (base === want || f.toLowerCase().replace(/\.md$/, "") === want) hits.push(f);
  }
  if (hits.length) {
    hits.sort();
    return { kind: "internal", path: hits[0] };
  }
  return { kind: "missing", target: t };
}

// ---- inline parser ----

// Finder returns the next index of a fixed delimiter at or after a
// position. The last answer is cached: if a search from i found k (or
// nothing), every search from j in [i, k] has the same answer. This keeps
// many unmatched delimiters (a hostile "[[[[[[..." line) linear.
function finder(s) {
  const cache = new Map();
  return (delim, from) => {
    const c = cache.get(delim);
    if (c && c.from <= from && (c.pos === -1 || c.pos >= from)) return c.pos;
    const pos = s.indexOf(delim, from);
    cache.set(delim, { from, pos });
    return pos;
  };
}

// Sticky: matches only at lastIndex, so a failed attempt costs a few chars.
const BARE_URL = /https?:\/\/[^\s<>"'`]+/iy;

const PUNCT = "\\`*_{}[]()#+-.!|<>~\"'";

function isWordChar(ch) {
  return ch !== undefined && /[\p{L}\p{N}]/u.test(ch);
}

// parseInline turns one block of text into inline nodes:
// text, code, strong, em, link {href, c}, wiki {target, label}, img {alt}, br.
export function parseInline(s, depth = 0) {
  const out = [];
  let buf = "";
  const flush = () => {
    if (buf) out.push({ t: "text", s: buf });
    buf = "";
  };
  if (depth > MAX_DEPTH) return [{ t: "text", s }];
  const next = finder(s);
  let i = 0;
  while (i < s.length) {
    const ch = s[i];
    if (ch === "\\" && i + 1 < s.length && PUNCT.includes(s[i + 1])) {
      buf += s[i + 1];
      i += 2;
      continue;
    }
    if (ch === "\n") {
      // Two trailing spaces or a backslash make a hard break; otherwise a space.
      if (buf.endsWith("  ")) {
        buf = buf.replace(/ +$/, "");
        flush();
        out.push({ t: "br" });
      } else {
        buf += " ";
      }
      i++;
      continue;
    }
    if (ch === "`") {
      let n = 1;
      while (s[i + n] === "`") n++;
      const fence = "`".repeat(n);
      const end = next(fence, i + n);
      if (end > 0) {
        flush();
        let code = s.slice(i + n, end).replace(/\n/g, " ");
        if (code.length > 2 && code.startsWith(" ") && code.endsWith(" ")) code = code.slice(1, -1);
        out.push({ t: "code", s: code });
        i = end + n;
        continue;
      }
      buf += fence;
      i += n;
      continue;
    }
    if (ch === "[" && s[i + 1] === "[") {
      const end = next("]]", i + 2);
      if (end > 0 && end - i < 300 && !s.slice(i + 2, end).includes("\n")) {
        const inner = s.slice(i + 2, end);
        const bar = inner.indexOf("|");
        const target = bar >= 0 ? inner.slice(0, bar) : inner;
        const label = bar >= 0 ? inner.slice(bar + 1) : inner;
        if (target.trim()) {
          flush();
          out.push({ t: "wiki", target: target.trim(), label: label.trim() || target.trim() });
          i = end + 2;
          continue;
        }
      }
    }
    if ((ch === "!" && s[i + 1] === "[") || ch === "[") {
      const img = ch === "!";
      const open = img ? i + 1 : i;
      const close = next("]", open + 1);
      if (close > 0 && s[close + 1] === "(") {
        const paren = next(")", close + 2);
        if (paren > 0) {
          let href = s.slice(close + 2, paren).trim();
          const t = href.match(/^(\S+)\s+["'(].*["')]$/);
          if (t) href = t[1];
          if (href.startsWith("<") && href.endsWith(">")) href = href.slice(1, -1);
          const label = s.slice(open + 1, close);
          flush();
          if (img) {
            out.push({ t: "img", alt: label, src: href });
          } else {
            out.push({ t: "link", href, c: parseInline(label, depth + 1) });
          }
          i = paren + 1;
          continue;
        }
      }
    }
    if (ch === "<") {
      const end = next(">", i + 1);
      if (end > 0 && end - i < 2050) {
        const inner = s.slice(i + 1, end);
        if (/^https?:\/\/[^\s<>]+$/i.test(inner)) {
          flush();
          out.push({ t: "link", href: inner, c: [{ t: "text", s: inner }] });
          i = end + 1;
          continue;
        }
      }
    }
    if ((ch === "h" || ch === "H") && !isWordChar(s[i - 1])) {
      BARE_URL.lastIndex = i;
      const m = BARE_URL.exec(s);
      if (m) {
        let url = m[0].replace(/[.,;:!?)\]]+$/, "");
        flush();
        out.push({ t: "link", href: url, c: [{ t: "text", s: url }] });
        i += url.length;
        continue;
      }
    }
    if (ch === "*" || ch === "_" || ch === "~") {
      const dbl = s[i + 1] === ch;
      if (ch === "~" && !dbl) {
        buf += ch;
        i++;
        continue;
      }
      // "_" only opens at a word boundary (snake_case stays text).
      if (ch === "_" && isWordChar(s[i - 1])) {
        buf += dbl ? "__" : "_";
        i += dbl ? 2 : 1;
        continue;
      }
      const delim = dbl ? ch + ch : ch;
      const start = i + delim.length;
      if (s[start] !== undefined && s[start] !== " ") {
        let end = next(delim, start + 1);
        if (!dbl) {
          // A single delimiter must not close on the first half of a double.
          while (end > 0 && s[end + 1] === ch) end = next(delim, end + 2);
        }
        if (end > 0 && s[end - 1] !== " " && !(ch === "_" && isWordChar(s[end + delim.length]))) {
          flush();
          const kind = ch === "~" ? "del" : dbl ? "strong" : "em";
          out.push({ t: kind, c: parseInline(s.slice(start, end), depth + 1) });
          i = end + delim.length;
          continue;
        }
      }
      buf += delim;
      i += delim.length;
      continue;
    }
    buf += ch;
    i++;
  }
  flush();
  return out;
}

// ---- block parser ----

const FENCE = /^ {0,3}(`{3,}|~{3,})\s*([^`\s]*)/;
const HEADING = /^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t#]*$/;
const HR = /^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$/;
const LIST = /^(\s*)([-*+]|\d{1,9}[.)])[ \t]+(.*)$/;
const QUOTE = /^ {0,3}> ?(.*)$/;
const TABLE_SEP = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/;

function splitRow(line) {
  let l = line.trim();
  if (l.startsWith("|")) l = l.slice(1);
  if (l.endsWith("|") && !l.endsWith("\\|")) l = l.slice(0, -1);
  const cells = [];
  let cur = "";
  for (let i = 0; i < l.length; i++) {
    if (l[i] === "\\" && l[i + 1] === "|") {
      cur += "|";
      i++;
    } else if (l[i] === "|") {
      cells.push(cur.trim());
      cur = "";
    } else {
      cur += l[i];
    }
  }
  cells.push(cur.trim());
  return cells;
}

function indentOf(s) {
  let n = 0;
  for (const ch of s) {
    if (ch === " ") n++;
    else if (ch === "\t") n += 4;
    else break;
  }
  return n;
}

// parseFrontmatter splits a leading "---" block off. Returns [entries, rest]
// where entries is a list of raw lines (shown as-is, never interpreted).
export function splitFrontmatter(text) {
  const m = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(text);
  if (!m) return [null, text];
  return [m[1].split(/\r?\n/), text.slice(m[0].length)];
}

// parse turns markdown into blocks:
// fm {lines}, h {level, c}, p {c}, code {lang, s}, quote {c: blocks},
// list {ordered, items: [{task, c: inline, sub: blocks}]}, hr,
// table {head: [inline], rows: [[inline]]}.
export function parse(text, depth = 0) {
  text = String(text).replace(/\r\n?/g, "\n");
  const blocks = [];
  if (depth === 0) {
    const [fm, rest] = splitFrontmatter(text);
    if (fm) blocks.push({ t: "fm", lines: fm });
    text = rest;
  }
  if (depth > MAX_DEPTH) {
    blocks.push({ t: "code", lang: "", s: text });
    return blocks;
  }
  const lines = text.split("\n");
  let i = 0;
  const para = [];
  const endPara = () => {
    if (para.length) blocks.push({ t: "p", c: parseInline(para.join("\n"), 0) });
    para.length = 0;
  };
  while (i < lines.length) {
    const line = lines[i];
    if (line.trim() === "") {
      endPara();
      i++;
      continue;
    }
    let m = FENCE.exec(line);
    if (m) {
      endPara();
      const fence = m[1];
      const body = [];
      i++;
      while (i < lines.length) {
        const l = lines[i];
        const t = l.trim();
        if (t.startsWith(fence[0].repeat(fence.length)) && t.replace(new RegExp("\\" + fence[0], "g"), "") === "") break;
        body.push(l);
        i++;
      }
      i++;
      blocks.push({ t: "code", lang: m[2] || "", s: body.join("\n") });
      continue;
    }
    if ((m = HEADING.exec(line))) {
      endPara();
      blocks.push({ t: "h", level: m[1].length, c: parseInline(m[2] || "", 0) });
      i++;
      continue;
    }
    if (HR.test(line)) {
      endPara();
      blocks.push({ t: "hr" });
      i++;
      continue;
    }
    if (QUOTE.test(line)) {
      endPara();
      const inner = [];
      while (i < lines.length && lines[i].trim() !== "") {
        const q = QUOTE.exec(lines[i]);
        inner.push(q ? q[1] : lines[i]);
        i++;
      }
      blocks.push({ t: "quote", c: parse(inner.join("\n"), depth + 1) });
      continue;
    }
    if (line.includes("|") && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1]) && lines[i + 1].includes("-")) {
      endPara();
      const head = splitRow(line).map((c) => parseInline(c, 0));
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim() !== "" && lines[i].includes("|")) {
        rows.push(splitRow(lines[i]).map((c) => parseInline(c, 0)));
        i++;
      }
      blocks.push({ t: "table", head, rows });
      continue;
    }
    if ((m = LIST.exec(line)) && (para.length === 0 || m[1].length === 0)) {
      endPara();
      const base = indentOf(m[1]);
      const ordered = /\d/.test(m[2]);
      const items = [];
      while (i < lines.length) {
        const l = lines[i];
        const lm = LIST.exec(l);
        if (lm && indentOf(lm[1]) === base) {
          let body = lm[3];
          let task = null;
          const tm = /^\[([ xX])\][ \t]+(.*)$/.exec(body);
          if (tm) {
            task = tm[1] !== " ";
            body = tm[2];
          }
          items.push({ task, lines: [body], sub: [] });
          i++;
          continue;
        }
        if (l.trim() === "") {
          // A blank line ends the list unless an indented line follows.
          if (i + 1 < lines.length && indentOf(lines[i + 1]) > base && lines[i + 1].trim() !== "") {
            i++;
            continue;
          }
          break;
        }
        if (indentOf(l) > base && items.length) {
          items[items.length - 1].sub.push(l);
          i++;
          continue;
        }
        if (!lm && items.length && !FENCE.test(l) && !HEADING.test(l) && !QUOTE.test(l) && !HR.test(l)) {
          // Lazy continuation of the last item's text.
          items[items.length - 1].lines.push(l.trim());
          i++;
          continue;
        }
        break;
      }
      blocks.push({
        t: "list",
        ordered,
        items: items.map((it) => ({
          task: it.task,
          c: parseInline(it.lines.join("\n"), 0),
          sub: it.sub.length ? parse(dedent(it.sub).join("\n"), depth + 1) : [],
        })),
      });
      continue;
    }
    para.push(line);
    i++;
  }
  endPara();
  return blocks;
}

function dedent(lines) {
  let min = Infinity;
  for (const l of lines) if (l.trim() !== "") min = Math.min(min, indentOf(l));
  if (!isFinite(min) || min === 0) return lines;
  return lines.map((l) => {
    let n = 0;
    let k = 0;
    while (k < l.length && n < min && (l[k] === " " || l[k] === "\t")) {
      n += l[k] === "\t" ? 4 : 1;
      k++;
    }
    return l.slice(k);
  });
}

// ---- diff lines ----

// classifyDiffLine maps a line of the server's unified diff to a kind.
// The first character decides; a "+@@" line is an added line, not a marker.
export function classifyDiffLine(line) {
  switch (line[0]) {
    case "+":
      return "add";
    case "-":
      return "del";
    case "@":
      return "hunk";
    default:
      return "ctx";
  }
}

// ESCAPED matches the \u{....} sequences the server writes for invisible
// characters (safe.Text), so the UI can highlight them.
export const ESCAPED = /\\u\{[0-9a-f]{4,6}\}/g;

// searchFiles filters file paths by a case-insensitive substring (client side).
export function filterPaths(paths, q) {
  const needle = String(q).trim().toLowerCase();
  if (!needle) return paths.slice();
  return paths.filter((p) => p.toLowerCase().includes(needle));
}
