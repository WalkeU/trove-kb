# Changelog

[Unreleased]
- 2026-11-08 - New Trove logo: a "trove" wordmark whose v is the approval tick, a matching icon (favicon and Apple touch icon) in the web UI, and refreshed README logo, social preview and hero animation
- 2026-11-03 release v0.1.10
- 2026-11-03 - Added an About page with the running version and the changelog, a version label in the header and an owner-only History page of approved and rejected proposals and owner actions; the version now comes from the VERSION file when the build sets none
- 2026-11-03 - Clearer messages for proposals made stale by a renamed folder, the old Settings banners clear when a new rename check starts and the rename dry run no longer returns an empty settings object
- 2026-11-03 release v0.1.9
- 2026-11-03 - Added renaming of a top-level folder on the Settings page (owner only, one commit, audited, the allowed list follows, never merges into an existing folder, dry run first; links inside notes are not rewritten)
- 2026-11-03 release v0.1.8
- 2026-11-03 - Fixed a wrong letter-case warning on the Settings page: new folder names were compared with the old list that the save replaces
- 2026-11-03 release v0.1.7
- 2026-11-03 - Fixed the Settings page: max files must be a whole number from 1 to 500 (0 was silently accepted) and allowed folders must be single top-level names (`a/b` was accepted)
- 2026-11-03 release v0.1.6
- 2026-11-02 - Added a Settings page for the owner (allowed folders, allowed extensions, max files per proposal; saved to `data_dir/settings.json`, no restart, audited, with a conflict warning before saving) and `validation.allowed_extensions` so other text files such as `.yml` or `.tf` can be stored (frontmatter for `.md` only; non-markdown files get a stricter `key: value` secret rule)
- 2026-11-03 release v0.1.5
- 2026-10-31 - Agents can now list and read other agents' non-draft proposals (read-only); new `trove list --all-agents`, `trove show <id>` and MCP tools `trove_proposals` and `trove_proposal` (output marked as untrusted data), drafts of other agents stay hidden and only the owner approves or rejects
- 2026-10-30 - Approval review: the whole file opens in a closable dialog with the changes highlighted (old/new line numbers), the BOM mark is labelled "[hidden BOM character]", and byte order marks are stripped from submitted content and from rendered notes
- 2026-10-31 release v0.1.4
- 2026-10-30 release v0.1.3
- 2026-10-30 - Fixed a syntax error in app.js that broke the whole web UI in v0.1.1
- 2026-10-30 release v0.1.2
- 2026-10-30 - Added opening the whole modified file in the approval review and a BOM badge instead of the raw \u{feff} escape
- 2026-10-30 release v0.1.1
