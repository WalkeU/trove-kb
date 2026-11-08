// Trove UI: pure helpers for the review view (no DOM).
//
// They turn the server's review payload into the structures the layouts
// draw: the change tree, numbered diff rows, side-by-side pairs and the
// changed span inside a modified line. Text stays exactly as the server
// sent it (already escaped); rendering decides how to show it.

// fileStatus maps a review file to added, modified or deleted.
export function fileStatus(f) {
  if (f && f.op === "delete") return "deleted";
  if (f && f.new) return "added";
  return "modified";
}

export const STATUS_LETTER = { added: "A", modified: "M", deleted: "D" };

const GAP = /^@@ (\d+) unchanged line\(s\) @@$/;

// parseDiff reads the server's diff text (unified with "@@ N unchanged
// line(s) @@" gap markers, or a whole-file diff) into numbered rows:
// {kind: "ctx"|"add"|"del", old, new, text} and {kind: "gap", count}.
// A line without a known marker becomes {kind: "note", text}.
export function parseDiff(text) {
  const src = String(text || "").split("\n");
  if (src.length && src[src.length - 1] === "") src.pop();
  const rows = [];
  let oldNo = 0;
  let newNo = 0;
  let added = 0;
  let removed = 0;
  for (const line of src) {
    const gap = GAP.exec(line);
    if (gap) {
      const n = Number(gap[1]);
      oldNo += n;
      newNo += n;
      rows.push({ kind: "gap", count: n });
      continue;
    }
    const mark = line[0];
    const body = line.slice(1);
    if (mark === "+") {
      newNo++;
      added++;
      rows.push({ kind: "add", old: 0, new: newNo, text: body });
    } else if (mark === "-") {
      oldNo++;
      removed++;
      rows.push({ kind: "del", old: oldNo, new: 0, text: body });
    } else if (mark === " ") {
      oldNo++;
      newNo++;
      rows.push({ kind: "ctx", old: oldNo, new: newNo, text: body });
    } else {
      rows.push({ kind: "note", text: line });
    }
  }
  return { rows, added, removed };
}

// splitRows pairs rows for a side-by-side view. Each run of removed lines
// followed by added lines is zipped row by row; unchanged lines sit on
// both sides. Result items: {left, right} (either may be null) or
// {gap: count} or {note: text}.
export function splitRows(rows) {
  const out = [];
  let i = 0;
  while (i < rows.length) {
    const r = rows[i];
    if (r.kind === "gap") { out.push({ gap: r.count }); i++; continue; }
    if (r.kind === "note") { out.push({ note: r.text }); i++; continue; }
    if (r.kind === "ctx") { out.push({ left: r, right: r }); i++; continue; }
    const dels = [];
    const adds = [];
    while (i < rows.length && rows[i].kind === "del") dels.push(rows[i++]);
    while (i < rows.length && rows[i].kind === "add") adds.push(rows[i++]);
    for (let k = 0; k < Math.max(dels.length, adds.length); k++) {
      out.push({ left: dels[k] || null, right: adds[k] || null });
    }
  }
  return out;
}

// pairChanges marks, inside each removed/added run, which rows have a
// partner, so a unified view can highlight the changed span of a line.
// Returns a Map row -> partner row.
export function pairChanges(rows) {
  const partner = new Map();
  for (const p of splitRows(rows)) {
    if (p.left && p.right && p.left !== p.right) {
      partner.set(p.left, p.right);
      partner.set(p.right, p.left);
    }
  }
  return partner;
}

// inlineSpan finds the changed middle of a modified line: the common
// prefix and suffix are left plain. Returns [start, end) of the changed
// part of a, or null when the lines share too little to be worth it.
// Escapes like \u{200b} are never split in half.
export function inlineSpan(a, b) {
  a = String(a);
  b = String(b);
  let pre = 0;
  const max = Math.min(a.length, b.length);
  while (pre < max && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < max - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  // Do not cut inside a \u{....} escape.
  const open = a.lastIndexOf("\\u{", pre);
  if (open !== -1 && open < pre && a.indexOf("}", open) >= pre) pre = open;
  if (pre + suf < 3 || pre + suf < Math.min(a.length, b.length) * 0.3) return null;
  return [pre, a.length - suf];
}

// changeTree builds a folder tree of the changed files. Folders with a
// single sub-folder and no files of their own are joined ("a/b").
// Folder: {name, path, dirs: [], files: [], counts: {added, modified, deleted}}.
// File: {name, path, status, index}.
export function changeTree(files) {
  const root = { name: "", path: "", dirs: new Map(), files: [] };
  files.forEach((f, index) => {
    const parts = String(f.path).split("/");
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!node.dirs.has(parts[i])) {
        node.dirs.set(parts[i], { name: parts[i], path: parts.slice(0, i + 1).join("/"), dirs: new Map(), files: [] });
      }
      node = node.dirs.get(parts[i]);
    }
    node.files.push({ name: parts[parts.length - 1], path: String(f.path), status: fileStatus(f), index });
  });
  const finish = (node) => {
    const counts = { added: 0, modified: 0, deleted: 0 };
    let dirs = [...node.dirs.values()].sort((x, y) => x.name.localeCompare(y.name)).map(finish);
    dirs = dirs.map((d) => {
      while (d.dirs.length === 1 && d.files.length === 0) {
        const c = d.dirs[0];
        d = { ...c, name: d.name + "/" + c.name };
      }
      return d;
    });
    for (const d of dirs) for (const k in counts) counts[k] += d.counts[k];
    const own = node.files.slice().sort((x, y) => x.name.localeCompare(y.name));
    for (const f of own) counts[f.status]++;
    return { name: node.name, path: node.path, dirs, files: own, counts };
  };
  return finish(root);
}

// treeOrder lists the file indexes in the order the tree shows them, so
// "next file" follows what the reader sees.
export function treeOrder(tree) {
  const out = [];
  const walk = (n) => {
    for (const d of n.dirs) walk(d);
    for (const f of n.files) out.push(f.index);
  };
  walk(tree);
  return out;
}

// summarize counts files per status and lines added/removed over a review.
export function summarize(files) {
  const s = { added: 0, modified: 0, deleted: 0, plus: 0, minus: 0 };
  for (const f of files) {
    s[fileStatus(f)]++;
    const d = parseDiff(f.diff);
    s.plus += d.added;
    s.minus += d.removed;
  }
  return s;
}

// language guesses a short label from the extension (shown, not used to
// colour anything).
export function language(path) {
  const m = /\.([a-z0-9]+)$/i.exec(String(path));
  const ext = m ? m[1].toLowerCase() : "";
  return { md: "Markdown", yml: "YAML", yaml: "YAML", json: "JSON", tf: "Terraform", sh: "Shell", ps1: "PowerShell", toml: "TOML", txt: "Text", conf: "Config", ini: "INI", py: "Python", go: "Go", js: "JavaScript", ts: "TypeScript", sql: "SQL", hcl: "HCL" }[ext] || (ext ? ext.toUpperCase() : "File");
}
