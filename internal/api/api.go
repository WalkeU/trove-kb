// Package api holds the JSON types shared by the HTTP server and client.
package api

import (
	"time"

	"trove/internal/gitrepo"
	"trove/internal/store"
)

// ErrorResp is returned with every non-2xx status.
type ErrorResp struct {
	Error   string   `json:"error"`
	Details []string `json:"details,omitempty"`
}

// HeadResp is the current commit of the knowledge base ("" if empty).
type HeadResp struct {
	Commit string `json:"commit"`
}

// FileChange summarizes one change without its content.
type FileChange struct {
	Path  string `json:"path"`
	Op    string `json:"op"`
	Bytes int    `json:"bytes"`
}

// Summary is a proposal as shown in lists. Status, StaleFiles and the
// overlap fields are computed at request time against the current HEAD.
type Summary struct {
	ID            string       `json:"id"`
	State         store.State  `json:"state"`
	Topic         string       `json:"topic"`
	Agent         string       `json:"agent"`
	Scope         []string     `json:"scope,omitempty"`
	Base          string       `json:"base"`
	Supersedes    string       `json:"supersedes,omitempty"`
	SupersededBy  string       `json:"superseded_by,omitempty"`
	Digest        string       `json:"digest,omitempty"`
	Files         []FileChange `json:"files"`
	Warnings      []string     `json:"warnings,omitempty"`
	CreatedAt     time.Time    `json:"created_at"`
	SubmittedAt   time.Time    `json:"submitted_at"`
	ExpiresAt     time.Time    `json:"expires_at"`
	AppliedCommit string       `json:"applied_commit,omitempty"`
	DecidedBy     string       `json:"decided_by,omitempty"`
	Reason        string       `json:"reason,omitempty"`
	Status        string       `json:"status,omitempty"` // ready | stale (open proposals only)
	StaleFiles    []string     `json:"stale_files,omitempty"`
	OverlapCount  int          `json:"overlap_count,omitempty"`
	Overlaps      []string     `json:"overlaps,omitempty"` // ids, approver only
}

// Detail is a summary plus the full change contents.
type Detail struct {
	Summary
	Changes []store.Change `json:"changes"`
}

// StatusResp is returned by GET /v1/status.
type StatusResp struct {
	Commit    string    `json:"commit"`
	Actor     string    `json:"actor"`
	Role      string    `json:"role"`
	Open      int       `json:"open"`
	Pending   int       `json:"pending"`
	Proposals []Summary `json:"proposals,omitempty"`
}

// BeginReq opens a draft.
type BeginReq struct {
	Topic string   `json:"topic"`
	Scope []string `json:"scope,omitempty"`
	Base  string   `json:"base,omitempty"` // default: HEAD
}

// ChangeReq writes or deletes one file in a server-side draft.
type ChangeReq struct {
	Path    string `json:"path"`
	Op      string `json:"op"`
	Content string `json:"content,omitempty"`
}

// SubmitReq freezes a draft. If Changes is nil, the server-side draft
// content is used; otherwise it replaces the draft content.
type SubmitReq struct {
	Changes []store.Change `json:"changes"`
}

// ApproveReq must carry the digest shown by review.
type ApproveReq struct {
	Digest string `json:"digest"`
}

// ApproveResp reports the commit created.
type ApproveResp struct {
	Commit   string  `json:"commit"`
	Proposal Summary `json:"proposal"`
}

// RejectReq carries the reason.
type RejectReq struct {
	Reason string `json:"reason"`
}

// RebaseResp holds the new draft and the old proposal (with content, for reference).
type RebaseResp struct {
	New Summary `json:"new"`
	Old Detail  `json:"old"`
}

// ReviewFile is one file of a review, with a sanitized diff.
type ReviewFile struct {
	Path string `json:"path"`
	Op   string `json:"op"`
	New  bool   `json:"new"`
	Diff string `json:"diff"`
	// FullDiff is the complete file after the change with the removed
	// and added lines marked (every line prefixed with ' ', '-' or '+',
	// nothing collapsed, sanitized like Diff). Empty for deletes and for
	// closed proposals. The UI shows it in the "whole file" dialog.
	FullDiff string `json:"full_diff,omitempty"`
}

// ReviewResp is returned by GET /v1/proposals/{id}/review.
type ReviewResp struct {
	Summary Summary      `json:"summary"`
	Files   []ReviewFile `json:"files"`
	Notice  string       `json:"notice"`
}

// ImportResp reports an import.
type ImportResp struct {
	Commit   string   `json:"commit"`
	Files    int      `json:"files"`
	Commits  int      `json:"commits"`
	Skipped  []string `json:"skipped,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// TreeResp lists files at HEAD.
type TreeResp struct {
	Commit string   `json:"commit"`
	Files  []string `json:"files"`
}

// FileResp is one file.
type FileResp struct {
	Commit  string `json:"commit"`
	Path    string `json:"path"`
	Content string `json:"content"`
	Draft   string `json:"draft,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}

// SearchResp lists search hits.
type SearchResp struct {
	Commit  string          `json:"commit"`
	Matches []gitrepo.Match `json:"matches"`
}

// VerifyResp reports an audit verification.
type VerifyResp struct {
	OK       bool   `json:"ok"`
	Lines    int    `json:"lines"`
	LastHash string `json:"last_hash"`
	Error    string `json:"error,omitempty"`
}
