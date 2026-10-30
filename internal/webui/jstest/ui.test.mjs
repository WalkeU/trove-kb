// Tests for the UI's markdown parser, link rules and DOM renderer.
// Run without installing anything (Node is only needed for this test,
// never for the build):
//   docker run --rm -v "$PWD:/src" -w /src node:20-alpine node --test internal/webui/jstest/
import test from "node:test";
import assert from "node:assert/strict";
import {
  parse, parseInline, safeExternal, resolveHref, resolveWiki, splitInvisible, joinPath, classifyDiffLine, filterPaths,
} from "../static/md.js";

// ---- a minimal fake DOM, enough for render.js ----
class Node {
  constructor(type) {
    this.nodeType = type;
    this.childNodes = [];
    this.parentNode = null;
  }
  appendChild(c) {
    if (c.nodeType === 11) {
      for (const k of [...c.childNodes]) this.appendChild(k);
      c.childNodes = [];
      return c;
    }
    c.parentNode = this;
    this.childNodes.push(c);
    return c;
  }
  get textContent() {
    if (this.nodeType === 3) return this.data;
    return this.childNodes.map((c) => c.textContent).join("");
  }
  set textContent(v) {
    this.childNodes = [];
    this.appendChild(new Text(String(v)));
  }
}
class Text extends Node {
  constructor(d) {
    super(3);
    this.data = d;
  }
}
class Element extends Node {
  constructor(tag) {
    super(1);
    this.tagName = tag.toUpperCase();
    this.attrs = {};
    this.dataset = {};
    this.className = "";
  }
  setAttribute(k, v) {
    this.attrs[k] = String(v);
  }
}
const ALLOWED_PROPS = new Set(["href", "rel", "target", "title", "referrerPolicy"]);
globalThis.document = {
  createElement: (t) =>
    new Proxy(new Element(t), {
      set(o, k, v) {
        if (typeof k === "string" && !(k in o) && !ALLOWED_PROPS.has(k)) throw new Error("unexpected property " + k);
        o[k] = v;
        return true;
      },
    }),
  createTextNode: (d) => new Text(d),
  createDocumentFragment: () => new Node(11),
};
const { renderBlocks } = await import("../static/render.js");

function walk(n, f) {
  f(n);
  for (const c of n.childNodes || []) walk(c, f);
}
function render(md, current = "notes/a.md", files = ["notes/a.md", "notes/b.md", "INDEX.md", "runbooks/deploy.md"]) {
  const root = new Element("article");
  renderBlocks(root, parse(md), { files: new Set(files), current });
  return root;
}
const SAFE_TAGS = new Set(["ARTICLE", "P", "H1", "H2", "H3", "H4", "H5", "H6", "A", "SPAN", "CODE", "PRE", "STRONG", "EM", "DEL", "BR", "UL", "OL", "LI", "BLOCKQUOTE", "HR", "TABLE", "THEAD", "TBODY", "TR", "TH", "TD", "DIV"]);

// ---- tests ----

test("hostile markdown never produces unsafe elements or links", () => {
  const hostile = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "[x](javascript:alert(1))",
    "[x](JaVaScRiPt:alert(1))",
    "[x]( javascript:alert(1))",
    "[x](java\tscript:alert(1))",
    "[x](data:text/html,<script>alert(1)</script>)",
    "[x](vbscript:msgbox)",
    "[x](//evil.example/a)",
    "[x](\\\\evil.example\\a)",
    "[x](file:///etc/passwd)",
    "<javascript:alert(1)>",
    "![a](https://evil.example/track.png)",
    "![a](javascript:alert(1))",
    "<iframe src=https://evil.example></iframe>",
    "[[javascript:alert(1)]]",
    "[x](https://ok.example/\u0000a)",
    "[x](http://exa​mple.com)",
    "<a href=\"javascript:alert(1)\">x</a>",
    "| a | b |\n|---|---|\n| [x](javascript:1) | <script> |",
    "> [x](data:,1)",
    "- [x](javascript:1)\n  - ![i](x.png)",
  ].join("\n\n");
  const root = render(hostile);
  walk(root, (n) => {
    if (n.nodeType !== 1) return;
    assert.ok(SAFE_TAGS.has(n.tagName), "unexpected element " + n.tagName);
    if (n.tagName === "A") {
      const h = n.href;
      const internal = h.startsWith("#/read/");
      const external = /^https?:\/\//.test(h);
      assert.ok(internal || external, "unsafe href " + h);
      if (external) {
        assert.equal(n.rel, "noopener noreferrer nofollow");
        assert.equal(n.target, "_blank");
        assert.ok(!/[\s\u0000-\u001f]/.test(h));
      }
    }
  });
  const text = root.textContent;
  assert.ok(text.includes("<script>alert(1)</script>"), "raw HTML stays visible as text");
  assert.ok(text.includes("[image: a]"), "images become text placeholders");
});

test("safeExternal allows only http and https", () => {
  assert.equal(safeExternal("https://example.com/a?b=1#c"), "https://example.com/a?b=1#c");
  assert.equal(safeExternal("http://example.com"), "http://example.com/");
  for (const bad of ["javascript:alert(1)", "data:text/html,x", "//example.com", "ftp://x", "https://", "https:// example.com", "https://exa​mple.com", "mailto:a@b", "  https://x.com", "https://x.com/\n"]) {
    assert.equal(safeExternal(bad), "", bad);
  }
});

test("relative links resolve inside the knowledge base only", () => {
  const files = new Set(["notes/a.md", "notes/b.md", "INDEX.md", "runbooks/deploy.md"]);
  assert.deepEqual(resolveHref("b.md", "notes/a.md", files), { kind: "internal", path: "notes/b.md" });
  assert.deepEqual(resolveHref("./b", "notes/a.md", files), { kind: "internal", path: "notes/b.md" });
  assert.deepEqual(resolveHref("../runbooks/deploy.md#step", "notes/a.md", files), { kind: "internal", path: "runbooks/deploy.md" });
  assert.deepEqual(resolveHref("/INDEX.md", "notes/a.md", files), { kind: "internal", path: "INDEX.md" });
  assert.deepEqual(resolveHref("../../../etc/passwd", "notes/a.md", files), { kind: "none" });
  assert.equal(resolveHref("missing.md", "notes/a.md", files).kind, "missing");
  assert.equal(resolveHref("#top", "notes/a.md", files).kind, "none");
  assert.equal(resolveHref("%ZZ", "notes/a.md", files).kind, "none");
  assert.equal(resolveHref("b%E2%80%8B.md", "notes/a.md", files).kind, "none");
  assert.equal(joinPath("a/b", "../../.."), "");
});

test("wikilinks resolve by path or file name", () => {
  const files = new Set(["notes/a.md", "notes/b.md", "INDEX.md", "runbooks/deploy.md"]);
  assert.deepEqual(resolveWiki("deploy", "notes/a.md", files), { kind: "internal", path: "runbooks/deploy.md" });
  assert.deepEqual(resolveWiki("b", "notes/a.md", files), { kind: "internal", path: "notes/b.md" });
  assert.deepEqual(resolveWiki("runbooks/deploy.md#x", "notes/a.md", files), { kind: "internal", path: "runbooks/deploy.md" });
  assert.deepEqual(resolveWiki("Deploy", "notes/a.md", files), { kind: "internal", path: "runbooks/deploy.md" });
  assert.equal(resolveWiki("nope", "notes/a.md", files).kind, "missing");
  const inl = parseInline("see [[deploy|the runbook]] now");
  assert.deepEqual(inl[1], { t: "wiki", target: "deploy", label: "the runbook" });
});

test("invisible characters are made visible, never dropped", () => {
  const s = "a​b‮c\u{E0041}d e️f\u0007g";
  const parts = splitInvisible(s);
  const cps = parts.filter((p) => p.t === "inv").map((p) => p.cp);
  assert.deepEqual(cps, [0x200b, 0x202e, 0xe0041, 0xa0, 0xfe0f, 0x7]);
  const root = render("x​y [l‮ink](b.md) `c⁦ode`");
  const t = root.textContent;
  assert.ok(t.includes("\\u{200b}") && t.includes("\\u{202e}") && t.includes("\\u{2066}"), t);
  assert.ok(!/[​‮⁦]/.test(t));
  // Plain text, spaces, tabs and newlines are untouched.
  assert.deepEqual(splitInvisible("a b\tc\nd é ő"), [{ t: "text", s: "a b\tc\nd é ő" }]);
});

test("frontmatter is shown as text and markdown structures parse", () => {
  const blocks = parse("---\ntitle: x\nstatus: current\n---\n# Head\n\ntext **bold** _em_ `code`\n\n- [ ] todo\n- [x] done\n  - nested\n\n```sh\nrm -rf /\n```\n\n| a | b |\n|---|---|\n| 1 | 2 |\n");
  assert.equal(blocks[0].t, "fm");
  assert.deepEqual(blocks[0].lines, ["title: x", "status: current"]);
  assert.deepEqual(blocks.map((b) => b.t), ["fm", "h", "p", "list", "code", "table"]);
  assert.equal(blocks[3].items[0].task, false);
  assert.equal(blocks[3].items[1].task, true);
  assert.equal(blocks[3].items[1].sub[0].t, "list");
  assert.equal(blocks[4].s, "rm -rf /");
  const p = blocks[2].c.map((n) => n.t);
  assert.deepEqual(p, ["text", "strong", "text", "em", "text", "code"]);
  assert.equal(parseInline("snake_case_name")[0].s, "snake_case_name");
});

test("hostile input stays fast (no quadratic blowup)", () => {
  const big = [
    "[".repeat(200000) + "]",
    "*a".repeat(100000),
    "<".repeat(200000) + ">",
    "h".repeat(200000),
    "`".repeat(50000),
    "[[".repeat(100000),
    "_".repeat(200000),
    "> ".repeat(2000) + "x",
    Array.from({ length: 50 }, (_, i) => " ".repeat(i * 2) + "- x").join("\n"),
  ];
  for (const s of big) {
    const t0 = Date.now();
    parse(s);
    const ms = Date.now() - t0;
    assert.ok(ms < 3000, "took " + ms + "ms for input starting " + JSON.stringify(s.slice(0, 10)));
  }
});

test("diff lines are classified by their first character", () => {
  assert.equal(classifyDiffLine("+@@ fake marker @@"), "add");
  assert.equal(classifyDiffLine("-x"), "del");
  assert.equal(classifyDiffLine("@@ 3 unchanged line(s) @@"), "hunk");
  assert.equal(classifyDiffLine(" ctx"), "ctx");
});

test("file name filter is a case-insensitive substring match", () => {
  assert.deepEqual(filterPaths(["a/Deploy.md", "b/x.md"], "deploy"), ["a/Deploy.md"]);
  assert.deepEqual(filterPaths(["a", "b"], "  "), ["a", "b"]);
});

test("a byte order mark gets a spelled-out label and is dropped from rendered markdown", async () => {
  const { appendText, appendEscaped } = await import("../static/render.js");
  const bom = String.fromCharCode(0xfeff);
  const esc = String.fromCharCode(92) + "u{feff}";
  for (const root of [appendText(new Element("div"), bom + "USPRIV"), appendEscaped(new Element("div"), esc + "USPRIV")]) {
    const mark = root.childNodes[0];
    assert.equal(mark.className, "inv bom");
    assert.equal(mark.textContent, "[hidden BOM character]");
    assert.equal(root.textContent, "[hidden BOM character]USPRIV");
  }
  // Other escapes keep their code point.
  assert.equal(appendEscaped(new Element("div"), String.fromCharCode(92) + "u{200b}x").textContent, String.fromCharCode(92) + "u{200b}x");
  const blocks = parse(bom + "---\ntitle: t\n---\n\n" + bom + "USPRIV\n");
  assert.equal(blocks[0].t, "fm");
  assert.ok(!JSON.stringify(blocks).includes(bom));
});
