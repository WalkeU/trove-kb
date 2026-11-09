// Tests for the review helpers (change tree, numbered diff rows, side by
// side pairing, changed span). Pure functions, no DOM:
//   docker run --rm -v "$PWD:/src" -w /src node:20-alpine node --test internal/webui/jstest/
import test from "node:test";
import assert from "node:assert/strict";
import { fileStatus, parseDiff, splitRows, pairChanges, inlineSpan, changeTree, treeOrder, summarize, language } from "../static/changes.js";

test("fileStatus maps op and new to added, modified, deleted", () => {
  assert.equal(fileStatus({ op: "put", new: true }), "added");
  assert.equal(fileStatus({ op: "put", new: false }), "modified");
  assert.equal(fileStatus({ op: "delete", new: false }), "deleted");
});

test("parseDiff numbers old and new lines across gap markers", () => {
  const d = parseDiff(" a\n-b\n+B\n c\n@@ 10 unchanged line(s) @@\n d\n+e\n");
  assert.equal(d.added, 2);
  assert.equal(d.removed, 1);
  const k = d.rows.map((r) => r.kind).join(",");
  assert.equal(k, "ctx,del,add,ctx,gap,ctx,add");
  assert.deepEqual([d.rows[0].old, d.rows[0].new], [1, 1]);
  assert.deepEqual([d.rows[1].old, d.rows[1].new], [2, 0]);
  assert.deepEqual([d.rows[2].old, d.rows[2].new], [0, 2]);
  assert.deepEqual([d.rows[3].old, d.rows[3].new], [3, 3]);
  // 10 skipped lines move both counters.
  assert.deepEqual([d.rows[5].old, d.rows[5].new], [14, 14]);
  assert.deepEqual([d.rows[6].old, d.rows[6].new], [0, 15]);
});

test("parseDiff keeps a line with an @@ prefix that is not a gap marker as a note, and an added @@ line as added", () => {
  const d = parseDiff("+@@ 3 unchanged line(s) @@\n(content is not retained for closed proposals)\n");
  assert.equal(d.rows[0].kind, "add");
  assert.equal(d.rows[0].text, "@@ 3 unchanged line(s) @@");
  assert.equal(d.rows[1].kind, "note");
});

test("parseDiff of an empty diff has no rows", () => {
  assert.deepEqual(parseDiff("").rows, []);
  assert.deepEqual(parseDiff(undefined).rows, []);
});

test("splitRows zips removed and added runs and keeps context on both sides", () => {
  const { rows } = parseDiff(" a\n-b\n-c\n+B\n d\n+e\n");
  const s = splitRows(rows);
  assert.equal(s.length, 5);
  assert.equal(s[0].left, s[0].right);
  assert.equal(s[1].left.text, "b");
  assert.equal(s[1].right.text, "B");
  assert.equal(s[2].left.text, "c");
  assert.equal(s[2].right, null);
  assert.equal(s[4].left, null);
  assert.equal(s[4].right.text, "e");
});

test("pairChanges links a removed line with its replacement", () => {
  const { rows } = parseDiff("-old value\n+new value\n+extra\n");
  const p = pairChanges(rows);
  assert.equal(p.get(rows[0]), rows[1]);
  assert.equal(p.get(rows[1]), rows[0]);
  assert.equal(p.has(rows[2]), false);
});

test("inlineSpan isolates the changed middle and skips unrelated lines", () => {
  assert.deepEqual(inlineSpan("port: 8080", "port: 9090"), [6, 9]);
  assert.deepEqual(inlineSpan("port: 9090", "port: 8080"), [6, 9]);
  assert.equal(inlineSpan("abc", "xyz"), null);
  // Never splits a \u{....} escape.
  const a = "x \\u{200b} y";
  const b = "x \\u{200c} y";
  const span = inlineSpan(a, b);
  assert.ok(span[0] <= a.indexOf("\\u{"));
});

test("changeTree groups by folder, counts statuses and joins single-child folders", () => {
  const files = [
    { path: "runbooks/deploy.md", op: "put", new: false },
    { path: "infra/servers/web/nginx.md", op: "put", new: true },
    { path: "infra/servers/web/old.md", op: "delete", new: false },
    { path: "INDEX.md", op: "put", new: false },
  ];
  const t = changeTree(files);
  assert.deepEqual(t.counts, { added: 1, modified: 2, deleted: 1 });
  assert.deepEqual(t.dirs.map((d) => d.name), ["infra/servers/web", "runbooks"]);
  assert.deepEqual(t.dirs[0].files.map((f) => f.status), ["added", "deleted"]);
  assert.equal(t.files[0].path, "INDEX.md");
  // Order follows the tree: folders first, then root files.
  assert.deepEqual(treeOrder(t), [1, 2, 0, 3]);
});

test("summarize counts files and lines", () => {
  const s = summarize([
    { path: "a.md", op: "put", new: true, diff: "+x\n+y\n" },
    { path: "b.md", op: "put", new: false, diff: " a\n-b\n+c\n" },
    { path: "c.md", op: "delete", new: false, diff: "-z\n" },
  ]);
  assert.deepEqual(s, { added: 1, modified: 1, deleted: 1, plus: 3, minus: 2 });
});

test("language labels common extensions", () => {
  assert.equal(language("x/y.md"), "Markdown");
  assert.equal(language("a.tf"), "Terraform");
  assert.equal(language("Makefile"), "File");
});
