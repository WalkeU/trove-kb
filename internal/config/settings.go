package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SettingsFile is the name of the runtime settings file inside data_dir.
const SettingsFile = "settings.json"

// Settings are the validation values the owner can change in the web UI.
// They live in data_dir/settings.json and override the same fields of the
// config file, so the hand-written config is never rewritten and may stay
// read-only (for example a mounted file).
type Settings struct {
	AllowedDirs       []string `json:"allowed_dirs"`
	AllowedExtensions []string `json:"allowed_extensions"`
	// MaxFiles is the most files one proposal may change. 0 keeps the
	// value of limits.max_files from the config file.
	MaxFiles int `json:"max_files,omitempty"`
}

// MaxFilesCeiling is the highest max_files the owner can set at runtime.
const MaxFilesCeiling = 500

// LoadSettings reads data_dir/settings.json. A missing file is not an
// error and returns nil. A damaged file is an error (fail closed), so a
// broken edit can never silently widen the rules.
func LoadSettings(dataDir string) (*Settings, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, SettingsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Settings
	if err := decodeStrict(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", SettingsFile, err)
	}
	if len(s.AllowedDirs) == 0 || len(s.AllowedExtensions) == 0 {
		return nil, fmt.Errorf("%s: allowed_dirs and allowed_extensions must not be empty", SettingsFile)
	}
	if s.MaxFiles < 0 || s.MaxFiles > MaxFilesCeiling {
		return nil, fmt.Errorf("%s: max_files must be between 1 and %d", SettingsFile, MaxFilesCeiling)
	}
	return &s, nil
}

// SaveSettings writes data_dir/settings.json atomically (temp file, fsync,
// rename) with owner-only permissions.
func SaveSettings(dataDir string, s Settings) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dataDir, SettingsFile+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(name) }
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, os.ErrPermission) {
		// Chmod is a no-op on some platforms; only a real failure matters.
		_ = err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, filepath.Join(dataDir, SettingsFile)); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// WithSettings returns v with the settings applied (nil leaves v alone).
func (v Validation) WithSettings(s *Settings) Validation {
	if s == nil {
		return v
	}
	v.AllowedDirs = append([]string(nil), s.AllowedDirs...)
	v.AllowedExtensions = append([]string(nil), s.AllowedExtensions...)
	return v
}

// WithSettings returns l with the settings applied (nil leaves l alone).
func (l Limits) WithSettings(s *Settings) Limits {
	if s != nil && s.MaxFiles > 0 {
		l.MaxFiles = s.MaxFiles
	}
	return l
}
