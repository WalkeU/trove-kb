// Package cli implements the trove command line.
package cli

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"trove"
	"trove/internal/api"
	"trove/internal/audit"
	"trove/internal/auth"
	"trove/internal/client"
	"trove/internal/config"
	"trove/internal/mcp"
	"trove/internal/safe"
	"trove/internal/server"
)

const usage = `trove: approval-gated knowledge base for AI agents

Server:
  trove init [--yes] [--dir trove] [flags]   first setup: config, data folder, tokens (see trove init -h)
  trove serve [--config trove.json] [--listen addr]   run the server (env TROVE_CONFIG)
  trove token new <name> <role>              create a token (role: reader|agent|approver)
  trove token hash                           hash a token read from stdin
  trove audit verify --file <audit.jsonl> [--expect-last <hash>]   verify the audit chain locally
  trove audit verify --remote                ask the server (approver)

Client (env TROVE_URL, TROVE_DIR; agent/reader token: TROVE_TOKEN or TROVE_TOKEN_FILE;
approver token: TROVE_APPROVER_TOKEN or TROVE_APPROVER_TOKEN_FILE, used only by
review, approve, reject, import and audit verify --remote; plain http to a
non-loopback host needs --insecure-http or TROVE_INSECURE_HTTP=1):
  trove sync                                 download HEAD into the mirror
  trove status                               local and server state
  trove begin "<topic>" [--scope a,b]        open a draft (agent)
  trove submit [--draft id] [--dry-run] [paths...]   submit local changes (agent)
  trove list [--state s]                     list proposals (own for agents)
  trove rebase <id>                          rebase a stale proposal (agent)
  trove abort <id>                           withdraw a draft or proposal (agent)
  trove review [id]                          list or review proposals (approver)
  trove approve <id> --digest <sha256>       approve (approver)
  trove reject <id> "<reason>"               reject (approver)
  trove import <dir> [--history] [--allow-secret-history]   one-time import (approver)
  trove instructions                         print the agent instructions
  trove mcp                                  MCP server on stdio (agent tools only)
  trove version
`

type env struct {
	out, errw io.Writer
	in        io.Reader // interactive input (trove init)
	tty       bool      // in is a terminal
}

// Run executes the command line and returns the exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	e := &env{out: stdout, errw: stderr, in: os.Stdin, tty: isTerminal(os.Stdin)}
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		err = e.initSetup(rest)
	case "serve":
		err = e.serve(rest)
	case "token":
		err = e.token(rest)
	case "audit":
		err = e.audit(rest)
	case "sync":
		err = e.sync(rest)
	case "status":
		err = e.status(rest)
	case "begin":
		err = e.begin(rest)
	case "submit":
		err = e.submit(rest)
	case "list":
		err = e.list(rest)
	case "rebase":
		err = e.rebase(rest)
	case "abort":
		err = e.abort(rest)
	case "review":
		err = e.review(rest)
	case "approve":
		err = e.approve(rest)
	case "reject":
		err = e.reject(rest)
	case "import":
		err = e.importKB(rest)
	case "instructions":
		err = e.instructions(rest)
	case "mcp":
		err = e.mcp(rest)
	case "version":
		fmt.Fprintln(stdout, "trove", trove.Version)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		// Error text can carry server or file name data: escape it.
		fmt.Fprintln(stderr, "error:", safe.Text(err.Error(), 0, 64<<10))
		return 1
	}
	return 0
}

// common client flags
type clientFlags struct {
	url       string
	tokenFile string
	dir       string
	insecure  bool
}

func (c *clientFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.url, "url", "", "server URL (default $TROVE_URL or the mirror state)")
	fs.StringVar(&c.tokenFile, "token-file", "", "file containing the token (default $TROVE_TOKEN / $TROVE_TOKEN_FILE)")
	fs.StringVar(&c.dir, "dir", "", "mirror directory (default $TROVE_DIR or the current directory)")
	fs.BoolVar(&c.insecure, "insecure-http", false, "allow sending the token over plain http to a non-loopback host (e.g. inside a VPN)")
}

func (c *clientFlags) mirrorDir() string {
	if c.dir != "" {
		return c.dir
	}
	if d := os.Getenv("TROVE_DIR"); d != "" {
		return d
	}
	return "."
}

// readToken reads the agent/reader token, or with approver=true the
// approver token, from separate variables, so an agent that inherits the
// owner's environment for TROVE_TOKEN never gets the approver token by
// accident, and approver commands never pick up an agent's TROVE_TOKEN.
func readToken(file string, approver bool) (string, error) {
	envTok, envFile := "TROVE_TOKEN", "TROVE_TOKEN_FILE"
	if approver {
		envTok, envFile = "TROVE_APPROVER_TOKEN", "TROVE_APPROVER_TOKEN_FILE"
	}
	if file == "" {
		if t := os.Getenv(envTok); t != "" {
			return strings.TrimSpace(t), nil
		}
		file = os.Getenv(envFile)
	}
	if file == "" {
		return "", fmt.Errorf("no token: set %s or %s (or --token-file)", envTok, envFile)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *clientFlags) insecureOK() bool {
	return c.insecure || os.Getenv("TROVE_INSECURE_HTTP") == "1"
}

// connect builds an agent/reader client; ws may be nil when no mirror is
// needed. The URL may come from the mirror state as a last resort.
func (c *clientFlags) connect(ws *client.Workspace) (*client.Client, error) {
	tok, err := readToken(c.tokenFile, false)
	if err != nil {
		return nil, err
	}
	u := c.url
	if u == "" {
		u = os.Getenv("TROVE_URL")
	}
	if u == "" && ws != nil {
		u = ws.State.URL
	}
	if u == "" {
		return nil, fmt.Errorf("no server URL: set TROVE_URL or --url")
	}
	if err := client.CheckTransport(u, c.insecureOK()); err != nil {
		return nil, err
	}
	return client.New(u, tok), nil
}

// connectApprover builds a client with the approver token. The URL must
// be given explicitly (--url or TROVE_URL): never from a mirror state
// file, which an agent can write.
func (c *clientFlags) connectApprover() (*client.Client, error) {
	tok, err := readToken(c.tokenFile, true)
	if err != nil {
		return nil, err
	}
	u := c.url
	if u == "" {
		u = os.Getenv("TROVE_URL")
	}
	if u == "" {
		return nil, fmt.Errorf("approver commands need an explicit server URL: set TROVE_URL or --url")
	}
	if err := client.CheckTransport(u, c.insecureOK()); err != nil {
		return nil, err
	}
	return client.New(u, tok), nil
}

func (c *clientFlags) workspace() (*client.Workspace, *client.Client, error) {
	ws, err := client.OpenWorkspace(c.mirrorDir())
	if err != nil {
		return nil, nil, err
	}
	cl, err := c.connect(ws)
	if err != nil {
		return nil, nil, err
	}
	return ws, cl, nil
}

// isTerminal reports whether f is a terminal, with the standard library
// only: a character device that is not the null device (docker run
// without -i connects stdin to /dev/null, which is a character device too).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if dn, err := os.Stat(os.DevNull); err == nil && os.SameFile(fi, dn) {
		return false
	}
	return true
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	return fs
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// line escapes a value for one terminal line, without truncating it.
// Every value that comes from the server (or from files an agent can
// write) goes through it: a compromised server must not control the
// terminal, and nothing an approver approves may be hidden.
func line(s string) string { return safe.Line(s, 0) }

// ---- server side commands ----

func (e *env) serve(args []string) error {
	cfg, err := serveConfig(args)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Serve(ctx, cfg, nil)
}

// serveConfig parses the serve flags and loads the config.
func serveConfig(args []string) (config.Config, error) {
	fs := newFlags("serve")
	cfgPath := fs.String("config", os.Getenv("TROVE_CONFIG"), "config file")
	listen := fs.String("listen", "", "listen address, overrides the config (e.g. 0.0.0.0:8470 inside a container whose port is published on 127.0.0.1 only)")
	if _, err := parse(fs, args); err != nil {
		return config.Config{}, err
	}
	if *cfgPath == "" {
		*cfgPath = "trove.json"
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return cfg, err
	}
	if *listen != "" {
		if err := checkListen(*listen); err != nil {
			return cfg, err
		}
		cfg.Listen = *listen
	}
	return cfg, nil
}

func (e *env) token(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trove token new <name> <role> | trove token hash")
	}
	switch args[0] {
	case "new":
		if len(args) != 3 {
			return fmt.Errorf("usage: trove token new <name> <reader|agent|approver>")
		}
		name, role := args[1], auth.Role(args[2])
		if !auth.ValidName(name) || !role.Valid() {
			return fmt.Errorf("invalid name or role")
		}
		tok, err := auth.NewToken(role)
		if err != nil {
			return err
		}
		fmt.Fprintf(e.out, "token (give it to the client, store it in a secret store, it is shown once):\n%s\n\n", tok)
		fmt.Fprintf(e.out, "server config entry (only the hash is stored):\n{\"name\": %q, \"role\": %q, \"sha256\": %q}\n", name, role, auth.Hash(tok))
		return nil
	case "hash":
		r := bufio.NewReader(os.Stdin)
		l, err := r.ReadString('\n')
		if err != nil && l == "" {
			return fmt.Errorf("reading token from stdin: %w", err)
		}
		fmt.Fprintln(e.out, auth.Hash(strings.TrimSpace(l)))
		return nil
	}
	return fmt.Errorf("unknown token subcommand %q", args[0])
}

func (e *env) audit(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("usage: trove audit verify --file <audit.jsonl> | --remote")
	}
	fs := newFlags("audit verify")
	file := fs.String("file", "", "audit log file")
	remote := fs.Bool("remote", false, "ask the server (approver token)")
	expect := fs.String("expect-last", "", "a previously saved last hash that must still be in the chain (detects truncation)")
	var cf clientFlags
	cf.register(fs)
	if _, err := parse(fs, args[1:]); err != nil {
		return err
	}
	if *remote {
		cl, err := cf.connectApprover()
		if err != nil {
			return err
		}
		v, err := cl.VerifyAudit()
		if err != nil {
			return err
		}
		if !v.OK {
			return fmt.Errorf("audit chain BROKEN after %d valid line(s): %s", v.Lines, v.Error)
		}
		fmt.Fprintf(e.out, "audit chain OK: %d line(s), last hash %s\n", v.Lines, line(v.LastHash))
		return nil
	}
	if *file == "" {
		return fmt.Errorf("--file or --remote is required")
	}
	res, err := audit.VerifyFileAnchor(*file, strings.TrimSpace(*expect))
	if err != nil {
		return fmt.Errorf("audit chain BROKEN after %d valid line(s): %w", res.Lines, err)
	}
	fmt.Fprintf(e.out, "audit chain OK: %d line(s), last hash %s\n", res.Lines, res.LastHash)
	if *expect != "" {
		after, err := res.CheckAnchor(strings.TrimSpace(*expect))
		if err != nil {
			return err
		}
		fmt.Fprintf(e.out, "saved hash found; %d line(s) appended since\n", after)
		return nil
	}
	fmt.Fprintln(e.out, "note: lines removed from the end cannot be detected from the file alone; save the last hash elsewhere and pass it with --expect-last")
	return nil
}

// ---- client commands ----

func (e *env) sync(args []string) error {
	fs := newFlags("sync")
	var cf clientFlags
	cf.register(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	ws, cl, err := cf.workspace()
	if err != nil {
		return err
	}
	commit, err := client.Sync(cl, ws, "")
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "synced %s to %s\n", line(ws.Dir), line(commit))
	return nil
}

func (e *env) printSummaries(list []api.Summary) {
	if len(list) == 0 {
		fmt.Fprintln(e.out, "(no proposals)")
		return
	}
	for _, s := range list {
		status := string(s.State)
		if s.Status != "" {
			status += "/" + s.Status
		}
		if s.OverlapCount > 0 {
			status += fmt.Sprintf(" overlap:%d", s.OverlapCount)
		}
		fmt.Fprintf(e.out, "%s  %-22s %-12s files:%-3d warn:%-3d %s\n", line(s.ID), line(status), line(s.Agent), len(s.Files), len(s.Warnings), line(s.Topic))
	}
}

func (e *env) status(args []string) error {
	fs := newFlags("status")
	var cf clientFlags
	cf.register(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	ws, cl, err := cf.workspace()
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "mirror:  %s\n", ws.Dir)
	if ws.Synced() {
		fmt.Fprintf(e.out, "local:   %s\n", line(ws.State.Commit))
		mods, problems, err := ws.Modifications()
		if err != nil {
			return err
		}
		for _, p := range problems {
			fmt.Fprintf(e.out, "  problem: %s\n", line(p))
		}
		for _, m := range mods {
			cov := "not submitted"
			if m.Covered != "" {
				cov = "submitted in " + m.Covered
			}
			fmt.Fprintf(e.out, "  %-8s %s (%s)\n", m.Kind, line(m.Path), line(cov))
		}
		for id, base := range ws.State.Drafts {
			fmt.Fprintf(e.out, "  open draft %s (base %s)\n", line(id), line(short(base)))
		}
	} else {
		fmt.Fprintln(e.out, "local:   not synced")
	}
	st, err := cl.Status()
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "server:  %s (%s as %s, %s)\n", line(cl.BaseURL), line(st.Commit), line(st.Actor), line(st.Role))
	if ws.Synced() && st.Commit != ws.State.Commit {
		fmt.Fprintln(e.out, "         the mirror is behind; run trove sync")
	}
	fmt.Fprintf(e.out, "queue:   %d open, %d pending\n", st.Open, st.Pending)
	if st.Role != string(auth.RoleReader) {
		e.printSummaries(st.Proposals)
	}
	return nil
}

func (e *env) begin(args []string) error {
	fs := newFlags("begin")
	scope := fs.String("scope", "", "comma separated folders the proposal is about")
	var cf clientFlags
	cf.register(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: trove begin \"<topic>\" [--scope a,b]")
	}
	ws, cl, err := cf.workspace()
	if err != nil {
		return err
	}
	var sc []string
	if *scope != "" {
		sc = strings.Split(*scope, ",")
	}
	s, err := client.Begin(cl, ws, pos[0], sc)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "draft %s opened (base %s)\n", line(s.ID), line(short(s.Base)))
	if head, err := cl.Head(); err == nil && head != ws.State.Commit {
		fmt.Fprintln(e.out, "note: the mirror is behind HEAD; changes to files modified since then will be stale")
	}
	return nil
}

func (e *env) submit(args []string) error {
	fs := newFlags("submit")
	draft := fs.String("draft", "", "draft id (default: the only open draft)")
	dry := fs.Bool("dry-run", false, "only show what would be submitted")
	var cf clientFlags
	cf.register(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	ws, cl, err := cf.workspace()
	if err != nil {
		return err
	}
	if *dry {
		changes, err := client.PendingChanges(ws, pos)
		if err != nil {
			return err
		}
		if len(changes) == 0 {
			fmt.Fprintln(e.out, "no local changes")
		}
		for _, c := range changes {
			fmt.Fprintf(e.out, "%-6s %s (%d bytes)\n", c.Op, line(c.Path), len(c.Content))
		}
		return nil
	}
	s, err := client.Submit(cl, ws, *draft, pos)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "submitted proposal %s\ndigest: %s\nstatus: %s\n", line(s.ID), line(s.Digest), line(s.Status))
	for _, f := range s.Files {
		fmt.Fprintf(e.out, "  %-6s %s\n", line(f.Op), line(f.Path))
	}
	for _, w := range s.Warnings {
		fmt.Fprintf(e.out, "  warning: %s\n", line(w))
	}
	fmt.Fprintln(e.out, "the owner reviews and approves it; there is nothing more to do here")
	return nil
}

func (e *env) list(args []string) error {
	fs := newFlags("list")
	state := fs.String("state", "", "filter: draft, pending, applied, rejected, aborted, expired, superseded, all (default: open)")
	var cf clientFlags
	cf.register(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	cl, err := cf.connect(nil)
	if err != nil {
		return err
	}
	l, err := cl.List(*state)
	if err != nil {
		return err
	}
	e.printSummaries(l)
	return nil
}

func oneID(fs *flag.FlagSet, args []string, usage string) (string, []string, error) {
	pos, err := parse(fs, args)
	if err != nil {
		return "", nil, err
	}
	if len(pos) < 1 {
		return "", nil, fmt.Errorf("usage: %s", usage)
	}
	return pos[0], pos[1:], nil
}

func (e *env) rebase(args []string) error {
	fs := newFlags("rebase")
	var cf clientFlags
	cf.register(fs)
	id, _, err := oneID(fs, args, "trove rebase <id>")
	if err != nil {
		return err
	}
	ws, cl, err := cf.workspace()
	if err != nil {
		return err
	}
	res, ref, err := client.Rebase(cl, ws, id)
	if ref != "" {
		fmt.Fprintf(e.out, "old proposal content saved for reference in %s\n", line(ref))
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "proposal %s superseded; new draft %s at %s\n", line(id), line(res.New.ID), line(short(res.New.Base)))
	fmt.Fprintln(e.out, "redo the change on the fresh files, then run trove submit")
	return nil
}

func (e *env) abort(args []string) error {
	fs := newFlags("abort")
	var cf clientFlags
	cf.register(fs)
	id, _, err := oneID(fs, args, "trove abort <id>")
	if err != nil {
		return err
	}
	ws, cl, err := cf.workspace()
	if err != nil {
		return err
	}
	if _, err := cl.Abort(id); err != nil {
		return err
	}
	if err := client.Forget(ws, id); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "proposal %s aborted\n", line(id))
	return nil
}

func (e *env) review(args []string) error {
	fs := newFlags("review")
	var cf clientFlags
	cf.register(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	cl, err := cf.connectApprover()
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		l, err := cl.List("pending")
		if err != nil {
			return err
		}
		e.printSummaries(l)
		if len(l) > 0 {
			fmt.Fprintln(e.out, "\nrun trove review <id> for the diff")
		}
		return nil
	}
	rv, err := cl.Review(pos[0])
	if err != nil {
		return err
	}
	s := rv.Summary
	fmt.Fprintf(e.out, "NOTE: %s\n\n", line(rv.Notice))
	fmt.Fprintf(e.out, "proposal:   %s\n", line(s.ID))
	fmt.Fprintf(e.out, "topic:      %s\n", line(s.Topic))
	fmt.Fprintf(e.out, "agent:      %s\n", line(s.Agent))
	fmt.Fprintf(e.out, "state:      %s %s\n", line(string(s.State)), line(s.Status))
	fmt.Fprintf(e.out, "base:       %s\n", line(s.Base))
	if s.Supersedes != "" {
		fmt.Fprintf(e.out, "supersedes: %s (earlier reviews do not carry over)\n", line(s.Supersedes))
	}
	if len(s.Scope) > 0 {
		fmt.Fprintf(e.out, "scope:      %s\n", line(strings.Join(s.Scope, ", ")))
	}
	if !s.ExpiresAt.IsZero() {
		fmt.Fprintf(e.out, "expires:    %s\n", s.ExpiresAt.Local().Format(time.RFC3339))
	}
	for _, f := range s.StaleFiles {
		fmt.Fprintf(e.out, "STALE:      %s changed since base\n", line(f))
	}
	for _, o := range s.Overlaps {
		fmt.Fprintf(e.out, "OVERLAP:    pending proposal %s touches the same file(s)\n", line(o))
	}
	if len(s.Warnings) > 0 {
		fmt.Fprintln(e.out, "warnings:")
		for _, w := range s.Warnings {
			fmt.Fprintf(e.out, "  ! %s\n", line(w))
		}
	}
	for _, f := range rv.Files {
		kind := f.Op
		if f.New {
			kind = "new"
		}
		fmt.Fprintf(e.out, "\n=== %s %s ===\n", line(kind), line(f.Path))
		// Never truncated: the approver must be able to see every byte that
		// the approval commits. Escaped, streamed to stdout (use a pager).
		fmt.Fprint(e.out, safe.Text(f.Diff, 0, 0))
	}
	fmt.Fprintf(e.out, "\ndigest: %s\n", line(s.Digest))
	if s.State == "pending" {
		fmt.Fprintf(e.out, "approve: trove approve %s --digest %s\n", line(s.ID), line(s.Digest))
		fmt.Fprintf(e.out, "reject:  trove reject %s \"<reason>\"\n", line(s.ID))
	}
	return nil
}

func (e *env) approve(args []string) error {
	fs := newFlags("approve")
	digest := fs.String("digest", "", "digest shown by trove review (required)")
	var cf clientFlags
	cf.register(fs)
	id, _, err := oneID(fs, args, "trove approve <id> --digest <sha256>")
	if err != nil {
		return err
	}
	if *digest == "" {
		return fmt.Errorf("--digest is required (copy it from trove review %s)", id)
	}
	cl, err := cf.connectApprover()
	if err != nil {
		return err
	}
	res, err := cl.Approve(id, *digest)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "proposal %s applied as commit %s\n", line(id), line(res.Commit))
	return nil
}

func (e *env) reject(args []string) error {
	fs := newFlags("reject")
	var cf clientFlags
	cf.register(fs)
	id, rest, err := oneID(fs, args, "trove reject <id> \"<reason>\"")
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("a reason is required")
	}
	cl, err := cf.connectApprover()
	if err != nil {
		return err
	}
	if _, err := cl.Reject(id, strings.Join(rest, " ")); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "proposal %s rejected\n", line(id))
	return nil
}

func (e *env) instructions(args []string) error {
	fs := newFlags("instructions")
	var cf clientFlags
	cf.register(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	cl, err := cf.connect(nil)
	if err != nil {
		return err
	}
	text, err := cl.Instructions()
	if err != nil {
		return err
	}
	fmt.Fprint(e.out, safe.Text(text, 0, 1<<20))
	return nil
}

func (e *env) mcp(args []string) error {
	fs := newFlags("mcp")
	var cf clientFlags
	cf.register(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	cl, err := cf.connect(nil)
	if err != nil {
		return err
	}
	// The MCP gateway is for agents: refuse to run with an approver token
	// (it would let the agent see every draft), and fail closed if the
	// role cannot be checked.
	st, err := cl.Status()
	if err != nil {
		return fmt.Errorf("cannot verify the token role: %w", err)
	}
	if st.Role == string(auth.RoleApprover) {
		return fmt.Errorf("trove mcp refuses to run with an approver token; give the agent an agent or reader token")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return mcp.Run(ctx, cl, os.Stdin, os.Stdout)
}

// ---- import ----

func (e *env) importKB(args []string) error {
	fs := newFlags("import")
	history := fs.Bool("history", false, "import the git history of <dir> (must be a git repository)")
	allowHist := fs.Bool("allow-secret-history", false, "with --history: report secrets found only in older versions as warnings instead of refusing")
	var cf clientFlags
	cf.register(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: trove import <dir> [--history]")
	}
	src := pos[0]
	cl, err := cf.connectApprover()
	if err != nil {
		return err
	}
	var res api.ImportResp
	if *history {
		res, err = importBundle(e, cl, src, *allowHist)
	} else {
		res, err = importTar(e, cl, src)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "imported %d file(s), %d commit(s); HEAD %s\n", res.Files, res.Commits, line(res.Commit))
	for _, s := range res.Skipped {
		fmt.Fprintf(e.out, "  skipped: %s\n", line(s))
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(e.out, "  WARNING: %s\n", line(w))
	}
	if len(res.Warnings) > 0 {
		fmt.Fprintln(e.out, "possible secrets remain in the imported history; rotate them")
	}
	return nil
}

func gitIn(dir string, args ...string) ([]byte, error) {
	// fsmonitor off: the source repository config must not run programs.
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "core.fsmonitor=false"}, args...)...)
	var errb strings.Builder
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out, nil
}

func importBundle(e *env, cl *client.Client, src string, allowHist bool) (api.ImportResp, error) {
	if _, err := gitIn(src, "rev-parse", "--verify", "HEAD"); err != nil {
		return api.ImportResp{}, fmt.Errorf("%s is not a git repository with commits: %w", src, err)
	}
	if out, err := gitIn(src, "status", "--porcelain"); err == nil && len(strings.TrimSpace(string(out))) > 0 {
		fmt.Fprintln(e.errw, "warning: the source has uncommitted changes; only committed history is imported")
	}
	tmp, err := os.MkdirTemp("", "trove-import-")
	if err != nil {
		return api.ImportResp{}, err
	}
	defer os.RemoveAll(tmp)
	bundle := filepath.Join(tmp, "kb.bundle")
	if _, err := gitIn(src, "bundle", "create", bundle, "HEAD"); err != nil {
		return api.ImportResp{}, err
	}
	f, err := os.Open(bundle)
	if err != nil {
		return api.ImportResp{}, err
	}
	defer f.Close()
	return cl.Import("bundle", allowHist, f)
}

func importTar(e *env, cl *client.Client, src string) (api.ImportResp, error) {
	root, err := filepath.Abs(src)
	if err != nil {
		return api.ImportResp{}, err
	}
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil || rel == "." {
				return err
			}
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if d.Name() == ".git" || d.Name() == client.MetaDir {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				fmt.Fprintf(e.errw, "skipping %s (not a regular file)\n", line(rel))
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			hdr := &tar.Header{Name: rel, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg, ModTime: time.Now()}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			_, err = tw.Write(data)
			return err
		})
		if err == nil {
			err = tw.Close()
		}
		pw.CloseWithError(err)
	}()
	res, err := cl.Import("tar", false, pr)
	pr.Close()
	return res, err
}
