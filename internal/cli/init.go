package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"trove/internal/auth"
	"trove/internal/config"
	"trove/internal/server"
	"trove/internal/store"
	"trove/internal/validate"
)

// trove init creates a ready-to-run setup in one folder:
//
//	<dir>/config/trove.json   server config (data_dir "../data", tokens_file "tokens.json")
//	<dir>/config/tokens.json  token hashes only
//	<dir>/data/               server data directory (empty)
//	<dir>/owner/<name>.token  approver token (owner only)
//	<dir>/agents/<name>.token agent tokens
//	<dir>/readers/<name>.token reader tokens (only if requested)
//
// The config and data folders match the Docker layout (/config read-only,
// /data writable), and the relative data_dir resolves the same way on the
// host and in the container. Every folder is 0700, every file 0600.

const (
	initConfigDir = "config"
	initDataDir   = "data"
	initOwnerDir  = "owner"
	initAgentDir  = "agents"
	initReaderDir = "readers"
	initPort      = "8470"
)

// initOptions are the setup choices, from flags or the wizard.
type initOptions struct {
	dir         string
	hostDir     string // dir as the host sees it (init inside a container); printed commands only
	listen      string
	allowedDirs []string
	owner       string
	agents      []string
	readers     []string
	force       bool
	allowRemote bool
	showTokens  bool
	welcome     bool // write the welcome note as the first commit
}

// listFlag is a repeatable flag that also accepts comma separated values.
type listFlag struct {
	vals []string
	set  bool
}

func (l *listFlag) String() string { return strings.Join(l.vals, ",") }

func (l *listFlag) Set(s string) error {
	l.set = true
	l.vals = append(l.vals, splitList(s)...)
	return nil
}

// splitList splits on commas and white space and drops empty items.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}

// errInitAborted is returned when the user declines or stdin ends.
var errInitAborted = errors.New("setup aborted, nothing was written")

func (e *env) initSetup(args []string) error {
	fs := newFlags("init")
	defDir := os.Getenv("TROVE_INIT_DIR")
	inContainer := defDir != ""
	if defDir == "" {
		defDir = "trove"
	}
	o := initOptions{}
	fs.StringVar(&o.dir, "dir", defDir, "folder for config, data and token files (env TROVE_INIT_DIR)")
	fs.StringVar(&o.hostDir, "host-dir", "", "the same folder as the host sees it, used in the printed commands (for init inside a container)")
	fs.StringVar(&o.listen, "listen", "127.0.0.1:"+initPort, "server listen address")
	allowed := fs.String("allowed-dirs", strings.Join(config.Default().Validation.AllowedDirs, ","), "comma separated top-level folders agents may write")
	fs.StringVar(&o.owner, "owner", "owner", "name of the approver (owner) token")
	var agents, readers listFlag
	fs.Var(&agents, "agent", "agent token name (repeatable, default \"agent\")")
	fs.Var(&readers, "reader", "reader token name (repeatable, optional)")
	yes := fs.Bool("yes", false, "no questions: use the flags and defaults (for scripts, CI and Docker)")
	fs.BoolVar(&o.force, "force", false, "overwrite an existing setup (all tokens are replaced)")
	fs.BoolVar(&o.allowRemote, "allow-non-loopback", false, "with --yes: accept a non-loopback --listen address")
	fs.BoolVar(&o.showTokens, "show-tokens", false, "also print the new tokens once (default: only the token files hold them)")
	noWelcome := fs.Bool("no-welcome", false, "leave the knowledge base empty (needed to trove import an existing one)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("usage: trove init [--yes] [--dir d] [--listen addr] [--allowed-dirs a,b] [--agent name]... [--reader name]... [--force]")
	}
	o.allowedDirs = splitList(*allowed)
	o.agents = agents.vals
	if !agents.set {
		o.agents = []string{"agent"}
	}
	o.readers = readers.vals
	o.welcome = !*noWelcome
	if !*yes {
		if !e.tty {
			return fmt.Errorf("stdin is not a terminal: run trove init --yes with flags (see trove init --help), or use docker run -it")
		}
		p := &prompter{r: bufio.NewReader(e.in), w: e.out}
		if err := e.initWizard(p, &o); err != nil {
			return err
		}
	}
	if err := checkInitOptions(&o); err != nil {
		return err
	}
	if inContainer && o.hostDir == "" && o.dir == os.Getenv("TROVE_INIT_DIR") {
		o.hostDir = "./trove"
		fmt.Fprintf(e.errw, "note: the printed commands assume %s is mounted from ./trove on the host; pass --host-dir \"$PWD/trove\" for absolute paths\n", o.dir)
	}
	if *yes && !loopbackListen(o.listen) {
		// The wizard asked already; without it, the flag is the confirmation.
		fmt.Fprintln(e.errw, nonLoopbackWarning(o.listen))
		if !o.allowRemote {
			return fmt.Errorf("refusing a non-loopback listen address without --allow-non-loopback")
		}
	}
	plan, err := buildInitPlan(o)
	if err != nil {
		return err
	}
	if err := applyInitPlan(plan, initHooks{}); err != nil {
		return err
	}
	cfg, err := selfCheck(plan)
	if err != nil {
		if rerr := plan.rollback(); rerr != nil {
			return fmt.Errorf("self-check failed: %v; rollback failed too: %v", err, rerr)
		}
		return fmt.Errorf("self-check failed, the setup was removed again: %w", err)
	}
	welcome := ""
	if o.welcome {
		if welcome, err = writeWelcome(plan, cfg); err != nil {
			if rerr := plan.rollback(); rerr != nil {
				return fmt.Errorf("welcome note: %v; rollback failed too: %v", err, rerr)
			}
			return fmt.Errorf("welcome note: %w (the setup was removed again; stop a running server first, or use --no-welcome)", err)
		}
	}
	e.printInitResult(plan, cfg, welcome)
	return nil
}

// ---- options ----

func checkName(kind, n string) error {
	// Names become file names too: refuse hidden names and Windows device
	// names on top of the token name rule.
	if !auth.ValidName(n) || validate.CheckPathSyntax(n) != nil {
		return fmt.Errorf("invalid %s name %q (allowed: A-Z a-z 0-9 . _ -, max 64, not starting with a dot, no device names)", kind, n)
	}
	return nil
}

// checkInitOptions validates and normalizes the options.
func checkInitOptions(o *initOptions) error {
	if strings.TrimSpace(o.dir) == "" {
		return fmt.Errorf("--dir must not be empty")
	}
	if err := checkListen(o.listen); err != nil {
		return err
	}
	dirs, err := cleanAllowedDirs(o.allowedDirs)
	if err != nil {
		return err
	}
	o.allowedDirs = dirs
	if len(o.agents) == 0 {
		return fmt.Errorf("at least one agent token is required")
	}
	seen := map[string]bool{}
	add := func(kind, n string) error {
		if err := checkName(kind, n); err != nil {
			return err
		}
		// Case-insensitive: the token files must not collide on Windows or macOS.
		k := strings.ToLower(n)
		if seen[k] {
			return fmt.Errorf("token name %q is used twice", n)
		}
		seen[k] = true
		return nil
	}
	if err := add("owner", o.owner); err != nil {
		return err
	}
	for _, n := range o.agents {
		if err := add("agent", n); err != nil {
			return err
		}
	}
	for _, n := range o.readers {
		if err := add("reader", n); err != nil {
			return err
		}
	}
	return nil
}

// cleanAllowedDirs checks the top-level folders. An empty list is refused
// (the server refuses it too), and so is anything but one plain segment.
func cleanAllowedDirs(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if strings.Contains(d, "/") || strings.Contains(d, "\\") {
			return nil, fmt.Errorf("allowed folder %q must be one top-level folder name", d)
		}
		if err := validate.CheckPathSyntax(d); err != nil {
			return nil, fmt.Errorf("allowed folder %q: %w", d, err)
		}
		if seen[validate.FoldKey(d)] {
			continue
		}
		seen[validate.FoldKey(d)] = true
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one allowed folder is required (an empty list is not \"everything\")")
	}
	return out, nil
}

func checkListen(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q (want host:port, e.g. 127.0.0.1:%s)", addr, initPort)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port in listen address %q", addr)
	}
	return nil
}

// loopbackListen mirrors the server's check: "localhost" or a loopback IP.
// An empty host (":8470") listens on every interface.
func loopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func nonLoopbackWarning(addr string) string {
	return fmt.Sprintf("WARNING: %s is not a loopback address. Trove has no TLS unless tls_cert/tls_key are set, so tokens and content would travel in clear text.\n"+
		"         Put it behind a VPN or an HTTPS reverse proxy and never expose it to a public network (alpha software, see SECURITY.md).", addr)
}

// ---- wizard ----

type prompter struct {
	r *bufio.Reader
	w io.Writer
}

// ask prints the question with the default and returns the answer (the
// default on an empty line). End of input aborts the setup.
func (p *prompter) ask(q, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(p.w, "%s [%s]: ", q, def)
	} else {
		fmt.Fprintf(p.w, "%s: ", q)
	}
	l, err := p.r.ReadString('\n')
	if err != nil && (l == "" || !errors.Is(err, io.EOF)) {
		fmt.Fprintln(p.w)
		return "", errInitAborted
	}
	l = strings.TrimSpace(l)
	if l == "" {
		return def, nil
	}
	return l, nil
}

func (p *prompter) confirm(q string, def bool) (bool, error) {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	a, err := p.ask(q+" ("+d+")", "")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(a) {
	case "":
		return def, nil
	case "y", "yes", "i", "igen":
		return true, nil
	}
	return false, nil
}

// askUntil repeats a question until check accepts the answer.
func (p *prompter) askUntil(q, def string, check func(string) error) (string, error) {
	for {
		a, err := p.ask(q, def)
		if err != nil {
			return "", err
		}
		if err := check(a); err != nil {
			fmt.Fprintln(p.w, "  ", err)
			continue
		}
		return a, nil
	}
}

func (e *env) initWizard(p *prompter, o *initOptions) error {
	fmt.Fprintln(e.out, "Trove setup. Press Enter to keep the value in brackets.")
	var err error
	if o.dir, err = p.askUntil("Folder for config, data and tokens", o.dir, func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("the folder must not be empty")
		}
		return nil
	}); err != nil {
		return err
	}
	for {
		if o.listen, err = p.askUntil("Listen address (keep 127.0.0.1 unless a VPN or TLS proxy protects the port)", o.listen, checkListen); err != nil {
			return err
		}
		if loopbackListen(o.listen) {
			break
		}
		fmt.Fprintln(e.out, nonLoopbackWarning(o.listen))
		ok, err := p.confirm("Listen on "+o.listen+" anyway?", false)
		if err != nil {
			return err
		}
		if ok {
			o.allowRemote = true
			break
		}
		o.listen = "127.0.0.1:" + initPort
	}
	a, err := p.askUntil("Top-level folders agents may write (comma separated)", strings.Join(o.allowedDirs, ","), func(s string) error {
		_, err := cleanAllowedDirs(splitList(s))
		return err
	})
	if err != nil {
		return err
	}
	o.allowedDirs = splitList(a)
	if o.owner, err = p.askUntil("Owner (approver) token name", o.owner, func(s string) error { return checkName("owner", s) }); err != nil {
		return err
	}
	a, err = p.askUntil("Agent token names (comma separated, at least one)", strings.Join(o.agents, ","), func(s string) error {
		if len(splitList(s)) == 0 {
			return fmt.Errorf("at least one agent token is required")
		}
		for _, n := range splitList(s) {
			if err := checkName("agent", n); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	o.agents = splitList(a)
	def := strings.Join(o.readers, ",")
	if def == "" {
		def = "none"
	}
	a, err = p.askUntil("Reader token names (read-only, optional)", def, func(s string) error {
		if s == "none" {
			return nil
		}
		for _, n := range splitList(s) {
			if err := checkName("reader", n); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	o.readers = nil
	if a != "none" {
		o.readers = splitList(a)
	}
	if err := checkInitOptions(o); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "\nfolder:  %s\nlisten:  %s\nfolders: %s\nowner:   %s\nagents:  %s\n",
		o.dir, o.listen, strings.Join(o.allowedDirs, ", "), o.owner, strings.Join(o.agents, ", "))
	if len(o.readers) > 0 {
		fmt.Fprintf(e.out, "readers: %s\n", strings.Join(o.readers, ", "))
	}
	fmt.Fprintln(e.out)
	if o.welcome, err = p.confirm("Start the knowledge base with a welcome note, so agents can sync right away? Say no if you will import an existing knowledge base", o.welcome); err != nil {
		return err
	}
	ok, err := p.confirm("Create the setup?", true)
	if err != nil {
		return err
	}
	if !ok {
		return errInitAborted
	}
	return nil
}

// ---- plan and apply ----

type initToken struct {
	name  string
	role  auth.Role
	file  string // absolute path of the token file
	value string
}

type initFile struct {
	path string
	data []byte
	// filled in by apply, for the rollback
	existed bool
	prev    []byte
	written bool
}

type initPlan struct {
	opts       initOptions
	root       string // absolute
	dirs       []string
	files      []*initFile // written in this order; trove.json last
	tokens     []initToken
	configPath string
	dataDir    string
	createdDir []string // folders created by apply, for the rollback
}

func buildInitPlan(o initOptions) (*initPlan, error) {
	root, err := filepath.Abs(o.dir)
	if err != nil {
		return nil, err
	}
	p := &initPlan{opts: o, root: root}
	sub := func(parts ...string) string { return filepath.Join(append([]string{root}, parts...)...) }
	p.dataDir = sub(initDataDir)
	p.dirs = []string{root, sub(initConfigDir), sub(initDataDir), sub(initOwnerDir), sub(initAgentDir)}
	if len(o.readers) > 0 {
		p.dirs = append(p.dirs, sub(initReaderDir))
	}
	add := func(name string, role auth.Role, dir string) error {
		tok, err := auth.NewToken(role)
		if err != nil {
			return err
		}
		p.tokens = append(p.tokens, initToken{name: name, role: role, file: sub(dir, name+".token"), value: tok})
		return nil
	}
	if err := add(o.owner, auth.RoleApprover, initOwnerDir); err != nil {
		return nil, err
	}
	for _, n := range o.agents {
		if err := add(n, auth.RoleAgent, initAgentDir); err != nil {
			return nil, err
		}
	}
	for _, n := range o.readers {
		if err := add(n, auth.RoleReader, initReaderDir); err != nil {
			return nil, err
		}
	}
	// tokens.json: hashes only, one entry per line like tokens.example.json.
	var tj strings.Builder
	tj.WriteString("[\n")
	for i, t := range p.tokens {
		b, err := json.Marshal(auth.TokenEntry{Name: t.name, Role: t.role, SHA256: auth.Hash(t.value)})
		if err != nil {
			return nil, err
		}
		tj.WriteString("  ")
		tj.Write(b)
		if i < len(p.tokens)-1 {
			tj.WriteString(",")
		}
		tj.WriteString("\n")
	}
	tj.WriteString("]\n")
	cfg := config.Default()
	cfg.Listen = o.listen
	cfg.DataDir = "../" + initDataDir // relative to the config file: same on the host and in Docker
	cfg.TokensFile = "tokens.json"
	cfg.Validation.AllowedDirs = o.allowedDirs
	cfg.Validation.ExtraSecretPatterns = []string{}
	cj, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	p.configPath = sub(initConfigDir, "trove.json")
	// Secrets are written after the hash list and before the config, so a
	// crash before them leaves no secret, and trove.json (written last)
	// only exists for a complete setup.
	p.files = append(p.files, &initFile{path: sub(initConfigDir, "tokens.json"), data: []byte(tj.String())})
	for _, t := range p.tokens {
		p.files = append(p.files, &initFile{path: t.file, data: []byte(t.value + "\n")})
	}
	p.files = append(p.files, &initFile{path: p.configPath, data: append(cj, '\n')})
	return p, nil
}

// initHooks are test hooks; the zero value is the production setup.
type initHooks struct {
	// beforeWrite runs before file i is written; an error simulates a
	// crash or a failed write at that point.
	beforeWrite func(i int) error
	// interrupt, if set, replaces the signal channel (tests).
	interrupt chan os.Signal
}

// applyInitPlan creates the folders and files. It never overwrites a file
// without --force, and on any error or interrupt it removes what it
// created (and restores what it overwrote), so no half-written setup with
// secrets is left behind.
func applyInitPlan(p *initPlan, h initHooks) error {
	if !p.opts.force {
		var exist []string
		for _, f := range p.files {
			if _, err := os.Lstat(f.path); err == nil {
				exist = append(exist, f.path)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if len(exist) > 0 {
			return fmt.Errorf("refusing to overwrite an existing setup (%s); use --force to replace it and all its tokens", strings.Join(exist, ", "))
		}
	}
	sig := h.interrupt
	if sig == nil {
		// Interrupts are held back while writing and handled by a rollback.
		sig = make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(sig)
	}
	interrupted := func() bool {
		select {
		case <-sig:
			return true
		default:
			return false
		}
	}
	fail := func(err error) error {
		if rerr := p.rollback(); rerr != nil {
			return fmt.Errorf("%v; rollback failed: %v", err, rerr)
		}
		return err
	}
	for _, d := range p.dirs {
		created, err := mkdirPrivate(d)
		if err != nil {
			return fail(dirError(d, err))
		}
		if created {
			p.createdDir = append(p.createdDir, d)
		}
		removeStaleTemps(d)
	}
	for i, f := range p.files {
		if interrupted() {
			return fail(errInitAborted)
		}
		if h.beforeWrite != nil {
			if err := h.beforeWrite(i); err != nil {
				return fail(err)
			}
		}
		if prev, err := os.ReadFile(f.path); err == nil {
			f.existed, f.prev = true, prev
		} else if !errors.Is(err, os.ErrNotExist) {
			return fail(err)
		}
		// WriteFileAtomic: temp file (mode 0600) in the same folder, fsync, rename.
		if err := store.WriteFileAtomic(f.path, f.data); err != nil {
			return fail(err)
		}
		f.written = true
		if err := os.Chmod(f.path, 0o600); err != nil {
			return fail(err)
		}
	}
	if interrupted() {
		return fail(errInitAborted)
	}
	return nil
}

// rollback removes the files written by apply (restoring overwritten
// ones) and the folders it created, newest first.
func (p *initPlan) rollback() error {
	var errs []string
	for i := len(p.files) - 1; i >= 0; i-- {
		f := p.files[i]
		if !f.written {
			continue
		}
		var err error
		if f.existed {
			err = store.WriteFileAtomic(f.path, f.prev)
		} else {
			err = os.Remove(f.path)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err.Error())
		}
		f.written = false
	}
	for i := len(p.createdDir) - 1; i >= 0; i-- {
		d := p.createdDir[i]
		removeStaleTemps(d)
		remove := os.Remove
		if d == p.dataDir {
			// Created by this run: it holds only what the welcome commit wrote.
			remove = os.RemoveAll
		}
		if err := remove(d); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err.Error())
		}
	}
	p.createdDir = nil
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// mkdirPrivate creates d (and missing parents) with mode 0700, or
// tightens an existing folder to 0700. It reports whether d was created.
func mkdirPrivate(d string) (bool, error) {
	fi, err := os.Stat(d)
	if err == nil {
		if !fi.IsDir() {
			return false, fmt.Errorf("%s exists and is not a folder", d)
		}
		// Best effort: a mounted folder owned by someone else cannot be changed.
		_ = os.Chmod(d, 0o700)
		return false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return false, err
	}
	return true, os.Chmod(d, 0o700)
}

func dirError(d string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("cannot create %s: %w (in Docker on Linux: create the host folder first and run the container with --user \"$(id -u):$(id -g)\")", d, err)
	}
	return err
}

// removeStaleTemps deletes temp files left by an interrupted atomic write.
func removeStaleTemps(dir string) {
	m, _ := filepath.Glob(filepath.Join(dir, ".tmp-*"))
	for _, f := range m {
		os.Remove(f)
	}
}

// selfCheck loads the written config with the same code trove serve uses
// (flags, config.Load, Validate, keyring) and checks that every token
// file maps to its name and role and that the data folder is writable.
func selfCheck(p *initPlan) (config.Config, error) {
	cfg, err := serveConfig([]string{"--config", p.configPath})
	if err != nil {
		return cfg, err
	}
	keys, err := auth.NewKeyring(cfg.Tokens)
	if err != nil {
		return cfg, err
	}
	for _, t := range p.tokens {
		b, err := os.ReadFile(t.file)
		if err != nil {
			return cfg, err
		}
		a, err := keys.Lookup(strings.TrimSpace(string(b)))
		if err != nil || a.Name != t.name || a.Role != t.role {
			return cfg, fmt.Errorf("token file %s does not match tokens.json", t.file)
		}
	}
	if cfg.Listen != p.opts.listen {
		return cfg, fmt.Errorf("listen address not stored as given")
	}
	f, err := os.CreateTemp(cfg.DataDir, ".tmp-*")
	if err != nil {
		return cfg, fmt.Errorf("data_dir %s is not writable: %w", cfg.DataDir, err)
	}
	f.Close()
	os.Remove(f.Name())
	return cfg, nil
}

// shellQuote quotes a path for a POSIX shell or PowerShell: single quotes,
// so nothing in it expands.
func shellQuote(v string, posix bool) string {
	if posix {
		return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
	}
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

// hostSep guesses the separator of a host path given with --host-dir: a
// backslash for a Windows path, a slash otherwise.
func hostSep(dir string) string {
	if strings.Contains(dir, `\`) && !strings.Contains(dir, "/") {
		return `\`
	}
	return "/"
}

// insideGitTree reports the git working tree that contains dir, if any.
func insideGitTree(dir string) string {
	for d := dir; ; {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

// ---- welcome note ----

// welcomePath is the file of the welcome commit (root files are allowed,
// and INDEX.md is the usual entry point of a knowledge base).
const welcomePath = "INDEX.md"

func welcomeNote(dirs []string, today string) string {
	return "---\ntitle: Welcome\nupdated: " + today + "\nstatus: current\n---\n\n" +
		"# Welcome\n\n" +
		"This is a Trove knowledge base: notes, runbooks and decisions that people and AI agents read.\n\n" +
		"Reading is open to every token. Changes are proposals that the owner approves:\n\n" +
		"1. `trove sync` downloads the current files.\n" +
		"2. `trove begin \"<topic>\" --scope <folder>` opens a draft.\n" +
		"3. Add or edit markdown files in the allowed folders: " + strings.Join(dirs, ", ") + ".\n" +
		"4. `trove submit` sends the proposal.\n" +
		"5. The owner reviews it with `trove review` and approves it on their own terminal.\n\n" +
		"Every note needs `title`, `updated` and `status` in its frontmatter. Never write a password, token or key here; write where it is stored instead.\n\n" +
		"This note can be changed or replaced with a proposal like any other.\n"
}

// writeWelcome writes the welcome note as the first commit through the
// engine (the same validation, commit and audit code as the server), with
// the data directory opened directly: init is an owner-side tool, so it
// needs neither the HTTP API nor a token. The instance lock refuses it
// while a server runs on the data directory. A knowledge base that is not
// empty is left alone ("" is returned).
func writeWelcome(p *initPlan, cfg config.Config) (string, error) {
	eng, err := server.Open(cfg, server.Options{})
	if err != nil {
		return "", err
	}
	defer eng.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	head, err := eng.Repo().Head(ctx)
	if err != nil {
		return "", err
	}
	if head != "" {
		return "", nil
	}
	owner := auth.Actor{Name: p.opts.owner, Role: auth.RoleApprover}
	note := welcomeNote(cfg.Validation.AllowedDirs, time.Now().Format("2006-01-02"))
	return eng.Bootstrap(owner, []store.Change{{Path: welcomePath, Op: store.OpPut, Content: note}})
}

// ---- output ----

// printInitResult prints the created files and the next steps. No token
// value is printed unless --show-tokens was given. welcome is the welcome
// commit, or "" if none was written.
func (e *env) printInitResult(p *initPlan, cfg config.Config, welcome string) {
	w := e.out
	// Shell syntax of the printed commands: the host's, guessed from
	// --host-dir when init runs inside a container.
	posix := runtime.GOOS != "windows"
	if p.opts.hostDir != "" {
		posix = hostSep(p.opts.hostDir) == "/"
	}
	shown := func(abs string) string {
		if p.opts.hostDir == "" {
			return abs
		}
		rel, err := filepath.Rel(p.root, abs)
		if err != nil {
			return abs
		}
		if rel == "." {
			return p.opts.hostDir
		}
		return strings.TrimRight(p.opts.hostDir, "/\\") + hostSep(p.opts.hostDir) + strings.ReplaceAll(filepath.ToSlash(rel), "/", hostSep(p.opts.hostDir))
	}
	q := func(v string) string { return shellQuote(v, posix) }
	sep := string(filepath.Separator)
	if p.opts.hostDir != "" {
		sep = hostSep(p.opts.hostDir)
	}
	_, port, _ := net.SplitHostPort(cfg.Listen)
	host, _, _ := net.SplitHostPort(cfg.Listen)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port)
	var owner initToken
	var clients []initToken
	for _, t := range p.tokens {
		if t.role == auth.RoleApprover {
			owner = t
		} else {
			clients = append(clients, t)
		}
	}
	agent := clients[0]
	setenv := func(k, v string) string {
		if posix {
			return "export " + k + "=" + q(v)
		}
		return "$env:" + k + " = " + q(v)
	}

	fmt.Fprintf(w, "\nTrove setup created in %s (folders 0700, files 0600)\n", shown(p.root))
	fmt.Fprintf(w, "  %-34s server config, token hashes only (mount read-only)\n", shown(filepath.Join(p.root, initConfigDir))+sep)
	fmt.Fprintf(w, "  %-34s server data (kb.git, proposals, audit log)\n", shown(filepath.Join(p.root, initDataDir))+sep)
	fmt.Fprintf(w, "  %-34s APPROVER token: owner only, never in an agent environment\n", shown(owner.file))
	for _, t := range clients {
		fmt.Fprintf(w, "  %-34s %s token\n", shown(t.file), t.role)
	}
	if runtime.GOOS == "windows" && p.opts.hostDir == "" {
		fmt.Fprintln(w, "note: Windows does not enforce the 0600/0700 modes; keep the folder inside your user profile.")
	}
	if g := insideGitTree(p.root); g != "" {
		fmt.Fprintf(e.errw, "WARNING: %s is inside the git working tree %s; make sure it is in .gitignore (it holds tokens).\n", p.root, g)
	}
	if p.opts.showTokens {
		fmt.Fprintln(w, "\nTokens (shown once; the token files above hold the same values):")
		for _, t := range p.tokens {
			fmt.Fprintf(w, "  %-10s %-20s %s\n", t.role, t.name, t.value)
		}
	}
	fmt.Fprintln(w, "\nThe token files are the only copy of the tokens. Keep owner/ away from agents: an agent")
	fmt.Fprintln(w, "running as your user can read it, so move the owner token into a password manager or a")
	fmt.Fprintln(w, "folder the agent cannot read, and mount only agents/ (or one token file) into an agent.")

	fmt.Fprintln(w, "\nNext steps")
	fmt.Fprintln(w, "\n1. Start the server (native binary):")
	fmt.Fprintf(w, "     trove serve --config %s\n", q(shown(p.configPath)))
	fmt.Fprintln(w, "   or with Docker (read-only, no capabilities, non-root, port on 127.0.0.1 only):")
	run := []string{"docker run -d --name trove --restart unless-stopped",
		"--read-only --cap-drop ALL --security-opt no-new-privileges:true --memory 128m --pids-limit 64 --tmpfs /tmp"}
	if posix {
		run = append(run, `--user "$(id -u):$(id -g)"`)
	}
	run = append(run, "-p 127.0.0.1:"+port+":"+port,
		"-v "+q(shown(filepath.Join(p.root, initConfigDir))+":/config:ro"),
		"-v "+q(shown(filepath.Join(p.root, initDataDir))+":/data"),
		"trove:local serve --listen 0.0.0.0:"+port)
	cont := " "
	if posix {
		cont = " \\\n       "
	}
	fmt.Fprintf(w, "     %s\n", strings.Join(run, cont))
	fmt.Fprintln(w, "   (--listen 0.0.0.0 applies inside the container only; -p 127.0.0.1 keeps the port local.")
	fmt.Fprintln(w, "   --user: the files belong to you with mode 0600; Docker Desktop on Windows does not need it.)")
	if !loopbackListen(cfg.Listen) {
		fmt.Fprintf(w, "   The native server listens on %s: use TLS (tls_cert/tls_key or an HTTPS proxy) or a VPN;\n", cfg.Listen)
		fmt.Fprintln(w, "   clients refuse plain http to a non-loopback host unless TROVE_INSECURE_HTTP=1.")
	}

	fmt.Fprintln(w, "\n2. Owner, in a separate terminal where no agent runs (never in a shell profile or .env):")
	fmt.Fprintf(w, "     %s\n     %s\n", setenv("TROVE_URL", url), setenv("TROVE_APPROVER_TOKEN_FILE", shown(owner.file)))
	switch {
	case welcome != "":
		fmt.Fprintln(w, "     trove review                         # pending proposals")
		fmt.Fprintf(w, "   The knowledge base starts with a welcome note (%s, commit %s), so agents can sync\n", welcomePath, short(welcome))
		fmt.Fprintln(w, "   right away. To import an existing knowledge base instead, create the setup with --no-welcome.")
	case p.opts.welcome:
		fmt.Fprintln(w, "     trove review                         # pending proposals")
		fmt.Fprintln(w, "   The knowledge base was not empty, so no welcome note was written; its content is unchanged.")
	default:
		fmt.Fprintln(w, "     trove import /path/to/kb --history   # once, before agents can sync (the server starts empty)")
		fmt.Fprintln(w, "     trove review                         # pending proposals")
	}

	fmt.Fprintln(w, "\n3. Agent environment (agent token only):")
	fmt.Fprintf(w, "     %s\n     %s\n", setenv("TROVE_URL", url), setenv("TROVE_TOKEN_FILE", shown(agent.file)))
	fmt.Fprintln(w, "     mkdir kb-mirror")
	fmt.Fprintln(w, "     trove sync --dir kb-mirror")

	fmt.Fprintln(w, "\n4. MCP client (agent token; trove must be on PATH, or use its full path). Claude Code:")
	fmt.Fprintf(w, "     claude mcp add trove -e TROVE_URL=%s -e TROVE_TOKEN_FILE=%s -- trove mcp\n", url, q(shown(agent.file)))
	fmt.Fprintln(w, "   Cursor (~/.cursor/mcp.json) or a Claude Code project file (.mcp.json):")
	type mcpServer struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
	}
	mcpCfg := map[string]any{"mcpServers": map[string]mcpServer{"trove": {
		Command: "trove",
		Args:    []string{"mcp"},
		Env:     map[string]string{"TROVE_URL": url, "TROVE_TOKEN_FILE": shown(agent.file)},
	}}}
	b, _ := json.MarshalIndent(mcpCfg, "     ", "  ")
	fmt.Fprintf(w, "     %s\n", b)
}
