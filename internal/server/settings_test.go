package server

import (
	"reflect"
	"strings"
	"testing"

	"trove/internal/api"
	"trove/internal/auth"
	"trove/internal/store"
)

func TestSettingsUpdate(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	submit := func(path, content string) error {
		d, err := ev.e.Begin(agent1, api.BeginReq{Topic: "t"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = ev.e.Submit(agent1, d.ID, []store.Change{put(path, content)})
		if err != nil {
			ev.e.Abort(agent1, d.ID)
		}
		return err
	}

	// Before: neither the folder nor the extension is allowed.
	wantKind(t, submit("newdir/c.yml", "a: b\n"), KindInvalid)

	// An agent cannot change the settings.
	_, err := ev.e.UpdateSettings(agent1, api.Settings{AllowedDirs: []string{"newdir"}, AllowedExtensions: []string{".md"}}, false)
	wantKind(t, err, KindForbidden)

	// The owner can; the new rules apply at once, without a restart.
	want := api.Settings{AllowedDirs: []string{"notes", "newdir"}, AllowedExtensions: []string{".md", ".yml"}}
	got, err := ev.e.UpdateSettings(owner, api.Settings{
		AllowedDirs:       []string{" notes/ ", "newdir", "notes", ""},
		AllowedExtensions: []string{".md", ".yml", ".yml"},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	got.Warnings = nil // conflicts are checked in TestSettingsWarnings
	want.MaxFiles = 50 // the default limit
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(ev.e.Settings(), want) {
		t.Fatalf("settings = %+v / %+v, want %+v", got, ev.e.Settings(), want)
	}
	if err := submit("newdir/c.yml", "a: b\n"); err != nil {
		t.Fatalf("yml in the new folder must be accepted now: %v", err)
	}
	// A folder that was removed is refused.
	wantKind(t, submit("other/x.md", md("x", "y")), KindInvalid)

	// It survives a restart (data_dir/settings.json).
	ev.reopen()
	if !reflect.DeepEqual(ev.e.Settings(), want) {
		t.Fatalf("after restart: %+v, want %+v", ev.e.Settings(), want)
	}

	// max_files: 0 keeps the value, out of range is refused, a valid value applies at once.
	if ev.e.Settings().MaxFiles != 50 {
		t.Fatalf("default max files = %d, want 50", ev.e.Settings().MaxFiles)
	}
	res, err := ev.e.UpdateSettings(owner, api.Settings{AllowedDirs: want.AllowedDirs, AllowedExtensions: want.AllowedExtensions, MaxFiles: 2}, false)
	if err != nil || res.MaxFiles != 2 {
		t.Fatalf("max files 2: %+v %v", res, err)
	}
	d, _ := ev.e.Begin(agent1, api.BeginReq{Topic: "many"})
	_, err = ev.e.Submit(agent1, d.ID, []store.Change{put("notes/m1.md", md("a", "b")), put("notes/m2.md", md("a", "b")), put("notes/m3.md", md("a", "b"))})
	wantKind(t, err, KindInvalid)
	ev.reopen()
	if ev.e.Settings().MaxFiles != 2 {
		t.Fatalf("max files after restart = %d, want 2", ev.e.Settings().MaxFiles)
	}
	want.MaxFiles = 2
	for _, bad := range []int{-1, 501} {
		_, err := ev.e.UpdateSettings(owner, api.Settings{AllowedDirs: want.AllowedDirs, AllowedExtensions: want.AllowedExtensions, MaxFiles: bad}, false)
		wantKind(t, err, KindInvalid)
	}

	// Invalid input changes nothing.
	for _, bad := range []api.Settings{
		{AllowedDirs: nil, AllowedExtensions: []string{".md"}},
		{AllowedDirs: []string{"notes"}, AllowedExtensions: nil},
		{AllowedDirs: []string{"notes"}, AllowedExtensions: []string{"YML"}},
		{AllowedDirs: []string{"../etc"}, AllowedExtensions: []string{".md"}},
		{AllowedDirs: []string{".git"}, AllowedExtensions: []string{".md"}},
		{AllowedDirs: []string{"a/b"}, AllowedExtensions: []string{".md"}},
	} {
		_, err := ev.e.UpdateSettings(owner, bad, false)
		wantKind(t, err, KindInvalid)
	}
	if !reflect.DeepEqual(ev.e.Settings(), want) {
		t.Fatalf("invalid updates changed the settings: %+v", ev.e.Settings())
	}
}

func TestSettingsWarnings(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	// A pending proposal in "notes" and a .yml file in the KB.
	ev.propose(agent1, "pending in notes", put("notes/new.md", md("n", "x")))

	// Dry run: "notes", "runbooks" and ".yml" conflict with the new lists.
	// Nothing is changed.
	before := ev.e.Settings()
	res, err := ev.e.UpdateSettings(owner, api.Settings{AllowedDirs: []string{"Notes", "renamed"}, AllowedExtensions: []string{".md"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(res.Warnings, "\n")
	for _, want := range []string{`Folder "notes" has`, `Folder "runbooks" has`, "differs from", "extension .yml", "cannot be approved"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning %q in:\n%s", want, joined)
		}
	}
	if !reflect.DeepEqual(ev.e.Settings(), before) {
		t.Fatalf("dry run changed the settings: %+v", ev.e.Settings())
	}

	// No conflict: no warnings.
	res, err = ev.e.UpdateSettings(owner, api.Settings{AllowedDirs: append(before.AllowedDirs, "extra", "artifacts"), AllowedExtensions: []string{".md", ".yml"}}, true)
	if err != nil || len(res.Warnings) != 0 {
		t.Fatalf("expected no warnings, got %v (%v)", res.Warnings, err)
	}
}

func TestSettingsCaseWarningIgnoresOldList(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	// Save a list with "zz" (no such folder in the KB), then rename it to "ZZ":
	// the old list is being replaced, so there is nothing to collide with.
	cur := ev.e.Settings()
	if _, err := ev.e.UpdateSettings(owner, api.Settings{AllowedDirs: append(cur.AllowedDirs, "zz", "artifacts"), AllowedExtensions: []string{".md", ".yml"}}, false); err != nil {
		t.Fatal(err)
	}
	res, err := ev.e.UpdateSettings(owner, api.Settings{AllowedDirs: append(cur.AllowedDirs, "ZZ", "artifacts"), AllowedExtensions: []string{".md", ".yml"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(res.Warnings, "\n"); strings.Contains(got, "differs from") {
		t.Errorf("unexpected case warning against the old list:\n%s", got)
	}
	// Two names of the new list that differ only in case still warn.
	res, err = ev.e.UpdateSettings(owner, api.Settings{AllowedDirs: append(cur.AllowedDirs, "zz", "ZZ", "artifacts"), AllowedExtensions: []string{".md", ".yml"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(res.Warnings, "\n"); !strings.Contains(got, "differs from") {
		t.Errorf("expected a case warning inside the new list, got:\n%s", got)
	}
}

func TestRenameFolder(t *testing.T) {
	files := defaultFiles()
	files["runbooks/ref.md"] = md("ref", "See notes/alpha.md for details.")
	ev := newEnv(t, nil, files)
	rename := func(a auth.Actor, from, to string, dry bool) (api.RenameResp, error) {
		return ev.e.RenameFolder(a, api.RenameReq{From: from, To: to}, dry)
	}

	// Only the approver may rename.
	_, err := rename(agent1, "notes", "notes2", false)
	wantKind(t, err, KindForbidden)

	// Dry run: reports files and the unrewritten reference, changes nothing.
	res, err := rename(owner, "notes", "notes2", true)
	if err != nil || res.Files != 2 {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	if got := strings.Join(res.Warnings, "\n"); !strings.Contains(got, "NOT rewritten") {
		t.Errorf("expected a reference warning, got:\n%s", got)
	}
	if _, ok := ev.readHead("notes/alpha.md"); !ok {
		t.Fatal("dry run moved files")
	}

	// Refused: unknown folder, same name, existing target, a name with a slash.
	_, err = rename(owner, "nope", "x", false)
	wantKind(t, err, KindNotFound)
	_, err = rename(owner, "notes", "notes", false)
	wantKind(t, err, KindInvalid)
	_, err = rename(owner, "notes", "runbooks", false)
	wantKind(t, err, KindConflict)
	_, err = rename(owner, "notes", "a/b", false)
	wantKind(t, err, KindInvalid)

	// The rename: files moved in one commit, allowed list followed.
	res, err = rename(owner, "notes", "notes2", false)
	if err != nil || res.Commit == "" || res.Files != 2 {
		t.Fatalf("rename: %+v %v", res, err)
	}
	if _, ok := ev.readHead("notes/alpha.md"); ok {
		t.Error("old path still exists")
	}
	if got, ok := ev.readHead("notes2/alpha.md"); !ok || !strings.Contains(got, "Alpha note.") {
		t.Errorf("new path missing or content changed: %q %v", got, ok)
	}
	dirs := strings.Join(ev.e.Settings().AllowedDirs, ",")
	if !strings.Contains(dirs, "notes2") || strings.Contains(","+dirs+",", ",notes,") {
		t.Errorf("allowed list did not follow: %s", dirs)
	}
	// The new folder accepts proposals, the old one no longer does.
	if _, err := ev.e.Begin(agent1, api.BeginReq{Topic: "t"}); err != nil {
		t.Fatal(err)
	}
	ev.reopen()
	if !strings.Contains(strings.Join(ev.e.Settings().AllowedDirs, ","), "notes2") {
		t.Error("renamed folder not persisted")
	}

	// Case-only rename of a folder is allowed (old paths disappear in the same commit).
	if _, err := rename(owner, "notes2", "Notes2", false); err != nil {
		t.Fatalf("case-only rename: %v", err)
	}
	if _, ok := ev.readHead("Notes2/beta.md"); !ok {
		t.Error("case-only rename did not move files")
	}
}
