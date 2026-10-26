# Trove design (first release)

Short technical design. The requirements live in the project plan; this file records how they are implemented and where the implementation differs.

## Packages

| Package | Role |
|---|---|
| `cmd/trove` | `main`, dispatches to `internal/cli` |
| `trove` (repo root) | embeds `AGENT-INSTRUCTIONS.md` |
| `internal/cli` | subcommands, flag parsing, terminal output |
| `internal/client` | HTTP client and the local mirror (`.trove/state.json`) |
| `internal/server` | `Engine` (all rules, one mutex) and the HTTP layer |
| `internal/store` | proposal JSON files, state machine, atomic writes, instance lock |
| `internal/gitrepo` | thin wrapper over the `git` binary (bare repo, plumbing only) |
| `internal/validate` | path, size, frontmatter, secret and warning rules |
| `internal/audit` | hash-chained JSONL log and verification |
| `internal/diff` | small line diff for review |
| `internal/safe` | escaping and truncation of untrusted text |
| `internal/auth` | token hashing, roles, constant-time lookup |
| `internal/config` | server config (JSON) |
| `internal/mcp` | stdio MCP gateway over the HTTP API (agent tools only) |
| `internal/webui` | embedded browser UI under `/ui/` (static HTML, CSS, vanilla JS modules) |

## Data directory

`kb.git/` (bare repo, branch `main`), `proposals/` (draft and pending), `archive/` (terminal states), `audit.jsonl`, `tmp/`, `trove.lock`.

## First setup (`trove init`)

- Creates `<dir>/config/` (`trove.json`, `tokens.json`), `<dir>/data/`, `<dir>/owner/` (approver token), `<dir>/agents/` and optionally `<dir>/readers/`; folders 0700, files 0600. `data_dir` is `../data`, relative to the config file, so the same layout works on the host and in Docker (`/config` read-only, `/data`).
- Wizard on a terminal; without one (or with `--yes`) flags only, never a prompt. Terminal check: character device that is not the null device (standard library only).
- Write order: `tokens.json` (hashes), token files, `trove.json` last, each with `store.WriteFileAtomic`. Any error or SIGINT/SIGTERM during the write phase rolls back (removes new files and created folders, restores files replaced with `--force`).
- Self-check: the config is loaded with the `serve` code path (`serveConfig`, `config.Load`, `Validate`), every token file must map to its name and role in the keyring, and `data_dir` must be writable.
- Welcome note (default, `--no-welcome` turns it off): after the self-check, init opens the data directory with `server.Open` (the instance lock refuses a running server) and calls `Engine.Bootstrap`: approver actor, only while `main` does not exist, the files pass `Rules.Check` like a proposal, `bootstrap-intent` audit line first (fail closed), commit built and moved with `update-ref <new> ""` like import, trailers `Trove-Bootstrap: welcome` and `Trove-Approver`, then a `bootstrap` audit line. A non-empty knowledge base is left alone. Import stays "empty repository only": it never replaces the welcome commit and its error points to `--no-welcome`.
- `trove serve --listen` overrides `listen`, so the config can stay on `127.0.0.1` while the container listens on `0.0.0.0` behind `-p 127.0.0.1:...`. The image sets `TROVE_INIT_DIR=/data` as the default init folder.

## HTTP API (all under `/v1`, `Authorization: Bearer <token>`)

| Method and path | Roles | Purpose |
|---|---|---|
| `GET /head`, `GET /snapshot` (tar, header `X-Trove-Commit`) | all | read |
| `GET /tree`, `GET /file?path=`, `GET /search?q=`, `GET /instructions` | all | read |
| `GET /status` | all | head, counts, visible proposals |
| `POST /proposals` | agent | begin (draft) |
| `POST /proposals/{id}/changes` | agent (own draft) | server-side write/delete (MCP) |
| `POST /proposals/{id}/submit` | agent (own) | freeze, validate, digest |
| `POST /proposals/{id}/abort`, `POST /proposals/{id}/rebase` | agent (own) | |
| `GET /proposals`, `GET /proposals/{id}` | agent (own), approver (all) | |
| `GET /proposals/{id}/review` | approver | diff, warnings, digest |
| `POST /proposals/{id}/approve` (`digest` required), `/reject` | approver | |
| `POST /import?mode=tar|bundle` | approver | one-time bootstrap, only into an empty repo |
| `GET /audit/verify` | approver | |

Outside `/v1`: `GET /healthz` (no token), `GET /ui/...` (static UI) and browser authentication under `/auth/`. The API accepts bearer tokens or owner browser cookies; cookie mutations require CSRF and Origin checks. All responses carry `nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Cache-Control: no-store` and same-origin COOP/CORP; API responses also `Content-Security-Policy: default-src 'none'; ...; sandbox`. No CORS headers.

## Web UI (`/ui/`)

- Embedded static assets are served before authentication, GET/HEAD only. The UI calls the existing `/v1` API using cookie authentication; rendering, complete review snapshots and digest checks remain unchanged.
- Browser auth lives in `internal/server/browser_auth.go`. `GET /auth/state` is public. First setup requires a configured approver bearer token plus matching new passwords (15-128 Unicode characters); it atomically stores the owner identity and Argon2id hash in `<data_dir>/browser-auth.json`. Setup cannot overwrite configured credentials.
- Password hashing: Argon2id, version implied by state version 1, 19 MiB memory, 2 iterations, parallelism 1, 16-byte random salt and 32-byte result. Login/setup/password change have a two-worker semaphore, per-peer attempt windows and a global attempt limit. No password or raw token is logged.
- Each browser device has a random 128-bit family ID, independent 256-bit opaque access/refresh secrets, a CSRF secret, creation time and expiration. Only hashes are persisted. Access lasts 10 minutes; refresh has a fixed 7-day expiry. At most 16 families are retained. State updates are copied, atomically persisted, then swapped under one mutex.
- Over HTTPS, access and refresh cookies are `__Host-` prefixed, host-only, `Secure; HttpOnly; SameSite=Strict; Path=/`. Optional direct tailnet HTTP uses separate cookie names without `Secure`, because browsers reject `Secure` cookies on HTTP. That mode is accepted only from direct `100.64.0.0/10` peers and requires an exact tailnet-IP `web_origin`. The separate CSRF cookie is readable by JavaScript and checked against both its stored hash and the custom request header. Credentials are never placed in localStorage, sessionStorage, URLs or JavaScript variables.
- Refresh rotates both authentication secrets and records consumed refresh hashes; reuse revokes the whole family. A 5-second in-memory cache can return the identical rotated response only for the exact previous access+refresh pair and matching CSRF value, covering concurrent requests/retries without accepting an old refresh token alone. The retry cache is not persisted. Expired and logged-out families cannot refresh.
- Browser-authenticated traffic normally requires direct TLS, or `X-Forwarded-Proto: https` from a peer in explicitly configured `web_trusted_proxies` CIDRs. Explicit tailnet HTTP mode accepts only direct `100.64.0.0/10` peers. Origin checks use `web_origin`, or the request scheme plus incoming Host; forwarded Host is never trusted. All cookie-authenticated mutations and auth POSTs require exact Origin, and session mutations also require CSRF. No CORS.
- `GET /auth/session` restores UI state. `POST /auth/logout`, `/auth/logout-all` and `/auth/password` revoke persisted families. Password changes require the current password and revoke every family. The Account page exposes these operations; the UI also logs out after 30 minutes idle.
- Existing bearer API auth remains for agents/readers and non-decision owner operations. Once browser credentials exist, approver bearer requests to `/approve` and `/reject` are refused, closing the old direct decision path. A configured browser-auth state load failure stops production startup.
- Recovery is a trusted local console operation: stop the instance, move `browser-auth.json` out of data, start and bootstrap with the offline owner token. Rebuilds do not reset credentials. Password authentication does not enforce human presence when an agent controls an authenticated browser; that browser remains a trust boundary.
- Markdown parsing, safe DOM construction, link policy, CSP, full diffs and proposal digest verification remain as before. Editing is still outside this phase.

## Formats

Proposal (`proposals/<id>.json`): `id, state, topic, agent, scope[], base, supersedes, superseded_by, changes[{path, op: put|delete, content}], digest, warnings[], created_at, submitted_at, updated_at, applied_commit, decided_by, reason`.

Digest: SHA-256 over a canonical byte stream: `trove-proposal-v1`, base, agent, topic, supersedes, then every change sorted by path (`op`, `path`, length, content). Paths cannot contain newlines, so the stream is unambiguous.

Audit line: `{seq, time, actor, role, event, proposal, result, detail, prev, hash}`; `hash = sha256(prev || json(line without hash))`, genesis `prev` is 64 zeros.

Commit trailers: `Trove-Proposal`, `Trove-Digest`, `Trove-Agent`, `Trove-Approver`, `Trove-Topic`. The topic is sanitized to one line, so content cannot inject a trailer line.

## State machine

`draft -> pending | aborted | expired`, `pending -> applied | rejected | aborted | expired | superseded`. Terminal states move the file to `archive/`. `ready`/`stale` and overlap warnings are computed on every read from the git trees (base vs HEAD blob ids per touched path), so they are always current after a HEAD change.

## Approve (one mutex, one process)

Role check, state `pending`, digest equal (constant time), digest recomputed from stored content, trailer lookup in HEAD history (idempotency), every touched path unchanged between base and HEAD, validation rerun, then a commit built with a temporary index file (`GIT_INDEX_FILE`) and `git update-ref main <new> <old>` (compare-and-swap). Only then the state is written. Startup recovery marks `pending` proposals whose id and digest trailers are already in HEAD history as `applied`.

## Deviations from the plan

1. Trailer names are `Trove-Proposal`/`Trove-Digest` (the plan section mentions `KB-*`; the task asked for `Trove-*`).
2. No working copy: the "temporary working copy" is a temporary git index plus plumbing. Nothing on disk can be contaminated between check and apply.
3. `draft` is an explicit state. Drafts count toward the per-agent and total limits (queue flooding protection) and expire like pending ones.
4. Rebase only for `pending` and `stale` proposals; the old one becomes `superseded` immediately and a new draft is created at HEAD.
5. "Out of topic folder" warning: if `begin --scope` was given, touching a path outside it warns; without scope, touching more than one top-level folder warns.
6. TOTP approval channel (channel 2) and notifications are not built (plan lists them as later work).
7. Invalid tokens are logged to stderr only; role violations by valid tokens go to the audit log (keeps the log from being flooded by anonymous requests).
8. (Superseded) Import secret findings now block, see below.
9. `INDEX.md` and `README.md` are frontmatter-exempt by default (a typical KB index has no frontmatter).
10. Requires Go 1.22+ (method and wildcard patterns of `http.ServeMux`).
11. The built-in UI also approves and rejects using the owner password session and exact reviewed digest. After browser setup, raw approver tokens cannot bypass that decision path. A browser controlled by an agent can still act as its logged-in owner; see SECURITY.md.

## Changes after the security reviews (2026-10-24)

- Approve validates against base and HEAD trees, checks `diff-tree` == touched paths, and writes an `approve-intent` audit line before moving the branch (fail closed; reject and import too).
- Review never truncates; submission limits bound the review size instead.
- Path rule shared by server, import and client (`validate.CheckPathSyntax`): character allowlist (ASCII plus precomposed Latin letters), no hidden segments, no `~`, case-insensitive collision checks. Content: control, tag and bidi characters block.
- Closed proposals drop their content (`content_dropped`, `size` kept); `LoadAll` keeps closed ones in memory only for `archive_memory_days`; per-agent daily quotas (`agent_bytes_per_day`, `agent_begins_per_day`) are computed from stored `bytes_written` and `created_at`.
- Submit and review run git reads, validation and diffs outside the engine mutex (draft revision re-checked).
- Import blocks on secrets (HEAD, and history for bundles unless `allow_secret_history`); bundle trees are validated and the branch removed on rejection.
- Audit lines must be byte-identical to their canonical encoding; `audit verify --expect-last` checks a saved hash.
- Client: separate approver token variables, explicit URL for approver commands, no plain-http token to non-loopback hosts without `--insecure-http`, `trove mcp` refuses approver tokens, all untrusted text escaped.
- `allowed_dirs` must not be empty (default: infra, projects, apps, claude, snippets, runbooks, decisions). `base` and `?commit=` accept only full hex ids.

## Changes after the re-verification reviews (2026-10-24, second round)

- One collision rule (`validate.PathIndex`, `validate.PathSetProblems`) for proposals (base or HEAD tree minus deletes, plus every put as it is checked), imports and client snapshots: file/folder conflicts and case twins of files and folders, also inside one proposal. The client checks the whole snapshot before writing.
- `trove review` prints everything (no line, file, path or warning truncation); every server field printed by the CLI is escaped; server log values are `%q` quoted and rate limited; the client never follows redirects.
- Bundle import: fetched into a temporary staging repository under `tmp/`, validated there (tree, modes, content rules, secrets in HEAD and in every history version, blobs larger than 4 x `max_file_bytes` refused), then fetched into `kb.git`. Nothing reaches `kb.git` on rejection, timeout or panic. Tar import checks and stores file by file and runs the content rules.
- Quota: per-hour write marks in the proposal (`writes`), counted by write time; submit reserves the quota under the mutex before validation (not refunded), one submit per agent at a time, at most 4 concurrent validations.
- Refused attempts go to `security.jsonl` (rate limited, rotated), not to the audit chain.
- Audit: `Open` reads only the tail (torn last line cut and reported), full verification streams in the background; failed appends truncate back; `VerifyAnchor` streams.
- Approve: content check outside the mutex, cached per digest; under the mutex only `CheckStructure` (tree rules) on base and HEAD; idempotent branch fail closed. State changes go through `commitState` (copy, save, then swap).
- A pending proposal that no longer fits HEAD structurally is shown `stale` and can be rebased.
- Secret rule: key at a word start, Hungarian/German key words, placeholder and code-snippet values ignored, `key: value` needs a quoted or password-shaped value. Path allowlist narrowed to U+00C0-U+017F letters (minus lookalikes); supplementary variation selectors block in content.
