<p align="center">
  <img src="assets/trove-logo.svg" alt="Trove" width="300">
</p>

<p align="center">
  <b>A knowledge base AI agents read, but only humans can change.</b><br>
  Multi-infra agent knowledge base: markdown in git, proposals in, approvals bound to a digest.
</p>

<p align="center">
  <a href="README.hu.md">Magyar</a> ·
  <a href="DESIGN.md">Design</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="AGENT-INSTRUCTIONS.md">Agent instructions</a>
</p>

> [!WARNING]
> **Alpha software. Do not use it in production or for confidential data.**
> Findings from two internal adversarial reviews (approval path, input handling) have been fixed, but there has been **no independent expert security review** yet. Do not point agents at a Trove you rely on, and do not expose it to a public network. See [SECURITY.md](SECURITY.md).

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/trove-hero.gif">
    <source media="(prefers-color-scheme: light)" srcset="assets/trove-hero-light.gif">
    <img src="assets/trove-hero.gif" width="1000" alt="An agent submits a diff as a proposal; the server checks path, content, secrets and frontmatter; the owner approves with the matching digest; the commit lands in kb.git while the audit log grows a hash chain.">
  </picture>
</p>

## The problem

- Agents work better with shared, written knowledge (runbooks, decisions, infra notes).
- Letting agents **write** that knowledge directly is risky: a wrong fact, a leaked secret or a prompt injection lands where every later agent reads it.
- Pull requests are a heavy workflow for a personal or small-team knowledge base, and an MCP client's "confirm" prompt is not a security boundary.

Trove keeps reading free and turns every change into a frozen proposal that a human approves on their own terminal (or in the built-in web UI).

## How it works

```mermaid
flowchart LR
  A["Agent<br>trove begin / submit"] -->|"frozen proposal<br>id + SHA-256 digest"| V{"Server validation<br>path, content,<br>secrets, frontmatter"}
  V -->|blocked| X["rejected at submit"]
  V -->|pending| R["Owner<br>trove review"]
  R -->|"trove approve id --digest"| C["Commit in kb.git<br>Trove-* trailers"]
  C --> L[("audit.jsonl<br>hash chain")]
```

1. **Propose.** `trove submit` freezes the proposal: an `id` and a SHA-256 `digest` over base, agent, topic, `supersedes` and the sorted changes. It cannot be edited afterwards.
2. **Validate.** On submit the server blocks bad paths, invalid content, secrets and missing frontmatter, and attaches warnings.
3. **Approve.** `trove review` shows the full diff, never truncated (long reviews: pipe through a pager, `trove review <id> | less -R`). `trove approve <id> --digest <hash>` only applies if the digest matches what was reviewed.
4. **Commit.** Under one mutex: digest recomputed from stored content, staleness and validation rechecked on base and current HEAD, commit built with a temporary index, `diff-tree` must equal the proposed paths, audit line written, then `update-ref` compare-and-swap. If anything fails, nothing is applied.

Also:

- **File-level staleness.** `ready` / `stale` is computed on every read against the fresh HEAD (a touched file, its parent or child path, or a case twin changed). Stale proposals are rebased with `trove rebase <id>`.
- **No queue.** Pending proposals are an unordered set; any `ready` one can be approved in any order. Overlaps are flagged, not blocked.
- **Hash-chained audit.** `<data>/audit.jsonl`, canonical JSON lines, checked by `trove audit verify`.
- **Small.** One Go binary (server, client, MCP gateway), standard library only, shells out to `git`.

## Quick start

`trove init` creates a complete first setup: config, data folder, an owner (approver) token and agent tokens. The main path is Docker:

```sh
docker build -t trove:local .                       # 1. build the image
mkdir trove                                         # 2. setup folder, owned by you
docker run --rm -it --user "$(id -u):$(id -g)" -v "$PWD/trove:/data" \
  trove:local init --host-dir "$PWD/trove"          # 3. wizard (Enter keeps the safe defaults)
docker run -d --name trove --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8470:8470 \
  -v "$PWD/trove/config:/config:ro" -v "$PWD/trove/data:/data" \
  trove:local serve --listen 0.0.0.0:8470           # 4. run the server
```

- At the end `init` checks the generated config with the same code `trove serve` uses and prints the next steps for your paths: the serve and Docker commands, the owner and agent environments (separately), MCP client config for Claude Code and Cursor, and the import command.
- `--user`: the files belong to you with mode 0600, so the container runs with your uid (still not root). On Docker Desktop (Windows, macOS) it can be left out; in PowerShell use `-v "${PWD}\trove:/data"`.
- `serve --listen 0.0.0.0:8470` applies inside the container only; `-p 127.0.0.1:...` keeps the port on the host's loopback.
- Without a terminal (CI, scripts, `docker run` without `-it`) `init` asks nothing and needs `--yes`:

```sh
trove init --yes --dir trove --agent laptop --agent ci --reader docs --allowed-dirs runbooks,decisions
```

What `init` creates (folders 0700, files 0600; Windows does not enforce these modes):

| Path | Content | Goes to |
|---|---|---|
| `trove/config/trove.json` | server config (`data_dir` `../data`, `tokens_file` `tokens.json`) | the server, read-only (`/config`) |
| `trove/config/tokens.json` | SHA-256 hashes only | the server, read-only |
| `trove/data/` | empty data directory | the server (`/data`) |
| `trove/owner/<name>.token` | approver token | the owner only, never an agent environment |
| `trove/agents/<name>.token`, `trove/readers/<name>.token` | agent and reader tokens | one file per agent |

Safe defaults and behavior:

- `listen` is `127.0.0.1:8470`. A non-loopback address (`0.0.0.0`, a LAN or VPN address) prints a warning (Trove has no TLS of its own) and needs a confirmation, or `--allow-non-loopback` with `--yes`.
- `validation.allowed_dirs` is `infra`, `projects`, `apps`, `claude`, `snippets`, `runbooks`, `decisions` unless you choose others (`--allowed-dirs`). An empty list is refused; it never means "everything".
- An existing setup is never overwritten without `--force`; `--force` replaces every token but keeps the knowledge base.
- Tokens are 256-bit random values. They are written only to the token files (atomically: temp file, then rename), never printed or logged; `--show-tokens` prints them once. An interrupted or failed run removes what it wrote.
- An agent running as your user can read `owner/` too: move the owner token into a password manager or a folder the agent cannot read.

The knowledge base starts with a short welcome note (`INDEX.md`), so agents can sync right away. `init` writes it as the first commit directly into the data folder (owner side, no token involved), marked with a `Trove-Bootstrap: welcome` trailer and recorded in the audit chain; it is only written into an empty knowledge base and never touches an existing one (not even with `--force`). To import an existing knowledge base instead, create the setup with `--no-welcome`: import only accepts an empty server and does not replace the welcome commit.

Native binary instead of Docker (requires Go 1.22+ and `git`):

```sh
go build -o trove ./cmd/trove                 # Windows: -o trove.exe
trove init                                    # creates ./trove
trove serve --config trove/config/trove.json
```

Manual setup without `init`: `trove token new <name> <role>` prints a token and its `{"name","role","sha256"}` line for `tokens.json` (see [`tokens.example.json`](tokens.example.json)); copy [`trove.example.json`](trove.example.json) to `trove.json` and set `data_dir`, `listen` and `validation.allowed_dirs`.

Agent side (agent token):

```sh
export TROVE_URL=http://127.0.0.1:8470        # or the https:// URL of your proxy
export TROVE_TOKEN_FILE="$PWD/trove/agents/agent.token"
mkdir -p ~/kb-mirror
trove sync --dir ~/kb-mirror
trove begin "backup retention" --scope runbooks
# edit files in the mirror
trove submit --dry-run
trove submit
```

Owner side (approver token, own terminal only):

```sh
export TROVE_URL=http://127.0.0.1:8470
export TROVE_APPROVER_TOKEN_FILE="$PWD/trove/owner/owner.token"
trove review                          # pending proposals
trove review <id>                     # full diff, warnings, digest
trove approve <id> --digest <digest>
trove reject <id> "reason"
```

Importing an existing KB (approver token, only into an empty server, so the setup needs `trove init --no-welcome`; any secret finding stops the import):

```sh
trove import /path/to/kb --history    # with git history (bundle), history is scanned too
trove import /path/to/kb              # files only, one commit
```

`--allow-secret-history` turns findings that exist **only** in older history into warnings. A finding in HEAD always blocks.

## Roles

One role per token. The server stores only the SHA-256 hash of each token.

| Role | Can | Cannot | Where it lives |
|---|---|---|---|
| `reader` | `sync`, `status`, search, read | open or submit proposals | background assistants, read-only tools |
| `agent` | read, plus own drafts: `begin`, `submit`, `rebase`, `abort`, `list` (own) | approve, reject, import, see other agents' proposals | the agent's environment |
| `approver` | `review`, `approve`, `reject`, `import`, `audit verify --remote` | treat it as full write access | the owner's machine only, never an agent environment |

Client token variables are separate on purpose:

| Variable | Token | Used by |
|---|---|---|
| `TROVE_TOKEN` / `TROVE_TOKEN_FILE` | agent or reader | `sync`, `status`, `begin`, `submit`, `list`, `rebase`, `abort`, `instructions`, `mcp` |
| `TROVE_APPROVER_TOKEN` / `TROVE_APPROVER_TOKEN_FILE` | approver | only `review`, `approve`, `reject`, `import`, `audit verify --remote` |

## Security model

Full threat model: [SECURITY.md](SECURITY.md).

**What protects what**

| Threat | Defense |
|---|---|
| Approving more than you saw | Review is never truncated; approval requires the reviewed digest; digest recomputed from stored content; `diff-tree` must equal the proposed paths |
| Race between check and apply | The whole approve runs under one mutex; the branch moves with `update-ref <new> <old>` compare-and-swap |
| Prompt injection, invisible Unicode | Control, Unicode tag (U+E0000-E007F) and bidi characters blocked in content; other invisible characters warned; client output escaped |
| Path tricks | `.md` only, character allowlist; no `..`, hidden segments, `~`, `\`, `:`, Windows device names, NFD or non-Latin scripts; case-insensitive collision checks; allowed folders only |
| Secrets in the KB | Regex secret filter on content, topic, scope, path and import (private keys, `name=value`, known token formats, one level of base64) |
| Token leakage | Hash-only storage, constant-time compare; tokens from env or file, never a flag; approver commands never read `TROVE_TOKEN` and take the URL only from `--url` / `TROVE_URL`; no token over plain `http://` to a non-loopback host without `--insecure-http` |
| Queue and disk flooding | Per-agent and total open limits, 7-day expiry, daily byte and begin quotas computed from stored metadata |
| Tampered audit log | Hash chain detects edited, removed or reordered lines; `--expect-last` detects truncation |

**What it does NOT protect against**

- Anyone who can write the data directory can bypass everything (repo, proposals, audit log).
- The audit log is tamper-evident, not immutable: a writer can recompute the whole chain. Save the last hash elsewhere.
- The secret filter catches accidental leaks, not deliberate evasion (splitting, custom encoding).
- Routine rubber-stamp approvals and false facts. The owner is the last filter.
- No HTTP rate limiting or connection limits, no full Unicode normalization, no warning for IPv6 addresses.
- A leaked agent token can fill the open queue until it is revoked. A leaked approver token is full write access.

**Operating rules**

- Never put the approver token in a shell profile or a shared `.env`. Provide it only for the approval, in a terminal that no agent runs in.
- Rejected requests are logged to `security.jsonl` (rotated, rate limited, not hash-chained), not to the audit log.
- The client does not follow redirects. If a reverse proxy sits in front, use the final `https://` URL.
- Check a knowledge base before importing it: `docker run --rm -v "<repo>:/src" -v "<kb>:/kb:ro" -e TROVE_KB_DIR=/kb -w /src golang:1.22 go test ./internal/validate -run KB -v`. Import blocks secrets, control characters, binary files, colliding paths and oversized files or history blobs.
- Report vulnerabilities privately through GitHub's "Report a vulnerability" (private vulnerability reporting) on the repository.

## Web UI

`trove serve` also serves a small browser UI at **`/ui/`** (for example `http://127.0.0.1:8470/ui/`). It is plain HTML, CSS and JavaScript embedded in the binary: no Node build, no CDN, no third-party script. `/`, `/healthz` and the `/v1` API are unchanged.

- **Read:** folder tree, rendered markdown (or the source), file name filter, content search (the existing `/v1/search`), `[[wikilinks]]` and relative links between notes, light and dark theme, usable on a phone.
- **Approve:** pending proposals, the full diff of one proposal (never truncated, same text as `trove review`), stale and overlap flags, warnings, the digest. **Approve** sends exactly the digest on screen (like `trove approve <id> --digest`), after fetching the review again and refusing if anything changed. **Reject** needs a reason. There is no "approve all". Stale proposals cannot be approved.
- **Sign in:** paste a token. A reader token gets the read view; the owner (approver) token gets both views; agent tokens are refused. The token stays in page memory, or in this tab's `sessionStorage` if you tick the box; never in `localStorage` or a cookie. The page locks after 30 minutes without activity.
- **Security model:** every action is a request to the existing API with `Authorization: Bearer`, so the server does all permission checks; the UI has no endpoint of its own. Knowledge base content is treated as hostile: it is never parsed as HTML (a small built-in markdown renderer creates DOM nodes with `textContent`), links are only notes of the knowledge base or `http(s)` URLs (`rel="noopener noreferrer"`), images and frames from content are never loaded, invisible characters are shown as `\u{....}`. A strict CSP (`default-src 'none'; script-src 'self'; ...`, no inline code) and `nosniff`, `no-referrer`, `no-store`, `frame-ancestors 'none'` headers back this up.
- **Not protected:** anything that controls the browser (an AI agent with browser automation, a malicious extension, a compromised OS) can read the token and click Approve. Use the owner token only in a browser profile no agent or untrusted extension controls; otherwise use `trove review` in a terminal. Details: [SECURITY.md](SECURITY.md).
- Turn it off with `"disable_ui": true` in `trove.json`.

## MCP

`trove mcp` is a stdio MCP server that runs with an agent (or reader) token. It **refuses to start with an approver token**.

Tools: `trove_search`, `trove_read`, `trove_list`, `trove_status`, `trove_begin`, `trove_write`, `trove_delete`, `trove_submit`, `trove_rebase`, `trove_abort`.

There is no approve, reject, import or review over MCP. Max message size is 8 MiB. Agents get their rules from `trove instructions` (the embedded [AGENT-INSTRUCTIONS.md](AGENT-INSTRUCTIONS.md)).

## Configuration

Server: generated by `trove init`, or copy [`trove.example.json`](trove.example.json) to `trove.json` (or point `TROVE_CONFIG` at it). Relative paths resolve against the folder of the config file.

| Key | Example value | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8470` | listen address; `trove serve --listen` overrides it (for example `0.0.0.0:8470` inside a container) |
| `data_dir` | `/data` | holds `kb.git/`, `proposals/`, `archive/`, `audit.jsonl`, `tmp/`, `trove.lock` |
| `tls_cert`, `tls_key` | empty | built-in TLS; or put a reverse proxy / VPN in front |
| `tokens_file` | `tokens.json` | token hashes (see [`tokens.example.json`](tokens.example.json)) |
| `limits.per_agent` / `limits.total` | `5` / `20` | open drafts and proposals |
| `limits.ttl_hours` | `168` | expiry (7 days) |
| `limits.max_file_bytes` / `limits.max_total_bytes` | 256 KiB / 1 MiB | per file / per proposal |
| `limits.agent_bytes_per_day` / `limits.agent_begins_per_day` | 20 MiB / `100` | daily per-agent quotas |
| `validation.allowed_dirs` | `infra`, `projects`, `apps`, `claude`, `snippets`, `runbooks`, `decisions` | top-level folders; an empty list is a config error |
| `validation.frontmatter_fields` | `title`, `updated`, `status` | required frontmatter (`INDEX.md`, `README.md` exempt) |
| `validation.extra_secret_patterns` | `[]` | your own secret regexes |
| `disable_ui` | `false` | `true` turns off the web UI under `/ui/` |

Client: environment variables (see [`.env.example`](.env.example)): `TROVE_URL`, `TROVE_DIR`, the token variables above, and `TROVE_INSECURE_HTTP=1` for a deliberate plain-http setup inside a VPN.

## Install

**Binary** (from source):

```sh
go build -o trove ./cmd/trove     # current platform
make build                        # dist/trove, static, trimmed
make cross                        # linux, darwin, windows (amd64, arm64) into dist/
```

**Docker**:

```sh
docker build -t trove:local .
cp docker-compose.example.yml docker-compose.yml   # expects a trove init folder at ./trove; adjust
docker compose up -d
```

The image runs as a non-root user on Alpine with `git`, works with a read-only root filesystem, exposes `8470`, reads `/config/trove.json` and keeps data in `/data`; `trove init` in the image writes its setup to `/data` (`TROVE_INIT_DIR`). A named volume is writable by the image user; a host folder on Linux needs `--user` (see Quick start). The example compose file binds to `127.0.0.1` only, drops all capabilities and sets memory and pid limits. Base images are pinned by tag only: for production builds pin them by digest (`FROM image:tag@sha256:...`) after checking the digest yourself.

## Limits and roadmap

First release limits: no TOTP second approval channel, no notifications, no HTTP rate limit, standard-library Unicode handling only, no editing in the web UI.

Planned (from the project plan, not built yet):

- [ ] Link-graph layer from `[[links]]` and frontmatter `related:` (markdown and git stay the source of truth)
- [ ] Line-level three-way merge of non-overlapping proposals (opt-in, flagged in review)
- [ ] Notification on submit (Telegram or similar) with an approve button
- [ ] TOTP-based approval through the agent, bound to the digest (second channel)
- [ ] Search index (SQLite FTS5 first)
- [x] Web UI, phases 1-2: read view and approval view (`/ui/`)
- [ ] Web UI, phase 3: editing (proposals from the browser)
- [ ] Multiple knowledge bases per server
- [ ] Stronger audit guarantees (separate logger, append-only attribute, remote collector)

## Contributing

Issues and pull requests are welcome. Please report vulnerabilities privately to the maintainers, not in a public issue (the contact will be defined before the public release).

```sh
gofmt -l .
go vet ./...
go test -race ./...
```

Without a local Go toolchain:

```sh
docker run --rm -v "$PWD:/src" -w /src golang:1.22 sh -c "gofmt -l . ; go vet ./... && go test -count=1 -race ./..."
```

The web UI's markdown renderer and link rules have their own tests (Node is used only to run them, never to build):

```sh
docker run --rm -v "$PWD:/src" -w /src node:20-alpine node --test internal/webui/jstest/
```

Tests create temporary git repositories, so `git` is required. The hero animation is a [HyperFrames](https://www.npmjs.com/package/hyperframes) composition in `assets/src/hero/` (re-render notes in its `<head>`).

## License

[MIT](LICENSE).
