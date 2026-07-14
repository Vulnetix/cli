package managedfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BackupSuffix is appended to a config file's path to hold its pre-write
// contents. Only whole-file writes (Structured, Merge) create one; a managed
// block is surgical and is reverted by removing the block, so restoring a
// backup there would discard unrelated edits the user made after install.
const BackupSuffix = ".vulnetix.bak"

// Mode is how a File's content is written, which is also how it is reverted.
type Mode int

const (
	// ModeBlock splices Content into the file between the markers, leaving the
	// rest of the file alone. The default.
	ModeBlock Mode = iota
	// ModeStructured replaces the whole file with Content. For formats where a
	// partial write is not expressible (XML, JSON documents with a fixed shape).
	ModeStructured
	// ModeMerge computes the new content from the existing content, folding our
	// keys into the user's real config.
	ModeMerge
)

// File is one config file to write.
type File struct {
	Path       string
	Content    string
	Structured bool
	// Merge, when set, computes the new file content from the file's existing
	// content instead of replacing it, so our keys can be folded into a user's
	// real config non-destructively.
	Merge func(existing string) (string, error)
	// Strip reverses a Merge write when no backup is available: it removes only
	// the keys we injected. The bool reports whether anything was removed.
	Strip func(path, existing string) (string, bool)
}

// Mode reports how f is written.
func (f File) Mode() Mode {
	switch {
	case f.Merge != nil:
		return ModeMerge
	case f.Structured:
		return ModeStructured
	default:
		return ModeBlock
	}
}

// WriteOutcome describes what UpsertFile did (or would do under dryRun).
type WriteOutcome struct {
	Mode     Mode
	Changed  bool // false means the file already held exactly this content
	BackedUp bool // a .vulnetix.bak was written (or would be)
}

// UpsertFile writes f, preserving everything in the file we do not own.
//
// A whole-file write (Structured or Merge) over an existing file backs that file
// up first — losing a hand-tuned ~/.m2/settings.xml because we replaced it is
// not an acceptable failure mode.
func UpsertFile(f File, m Markers, dryRun bool) (WriteOutcome, error) {
	out := WriteOutcome{Mode: f.Mode()}

	var existing string
	existed := false
	if data, err := os.ReadFile(f.Path); err == nil {
		existing = string(data)
		existed = true
	} else if !os.IsNotExist(err) {
		return out, err
	}

	var next string
	switch out.Mode {
	case ModeMerge:
		merged, err := f.Merge(existing)
		if err != nil {
			return out, err
		}
		next = merged
	case ModeStructured:
		next = f.Content
	default:
		next = Upsert(existing, Block(m, f.Content), m)
	}

	out.Changed = existing != next
	out.BackedUp = existed && out.Changed && out.Mode != ModeBlock

	if dryRun || !out.Changed {
		return out, nil
	}

	if err := os.MkdirAll(filepath.Dir(f.Path), 0700); err != nil {
		return out, err
	}
	if out.BackedUp {
		if err := os.WriteFile(f.Path+BackupSuffix, []byte(existing), 0600); err != nil {
			return out, fmt.Errorf("failed to back up %s: %w", f.Path, err)
		}
	}
	if err := os.WriteFile(f.Path, []byte(next), 0600); err != nil {
		return out, err
	}
	return out, nil
}

// RemoveOutcome describes what RemoveFile did (or would do under dryRun).
type RemoveOutcome struct {
	Mode    Mode
	Existed bool // the file was there at all
	// Configured is false when the file is absent, or holds no trace of us.
	Configured bool
	Restored   bool // the pre-write backup was put back
	Deleted    bool // the file was removed (it held nothing but our content)
	Stripped   bool // our keys/block were removed, the rest of the file kept
}

// RemoveFile reverses an UpsertFile.
//
// It never deletes a file that holds content we did not write: a whole-file mode
// prefers restoring the backup, falls back to Strip, and only deletes when the
// file still points at host and there is nothing to restore or strip.
func RemoveFile(f File, m Markers, host string, dryRun bool) (RemoveOutcome, error) {
	out := RemoveOutcome{Mode: f.Mode()}

	data, err := os.ReadFile(f.Path)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Existed = true
	existing := string(data)

	// A backup exists only for a whole-file write, and restoring it is always the
	// most faithful reversal available.
	if out.Mode != ModeBlock {
		bak := f.Path + BackupSuffix
		if bakData, berr := os.ReadFile(bak); berr == nil {
			out.Configured = true
			out.Restored = true
			if dryRun {
				return out, nil
			}
			if err := os.WriteFile(f.Path, bakData, 0600); err != nil {
				return out, err
			}
			if err := os.Remove(bak); err != nil {
				return out, err
			}
			return out, nil
		}
	}

	switch out.Mode {
	case ModeMerge:
		if f.Strip == nil {
			return out, nil
		}
		next, changed := f.Strip(f.Path, existing)
		if !changed {
			return out, nil
		}
		out.Configured = true
		out.Stripped = true
		if dryRun {
			return out, nil
		}
		return out, os.WriteFile(f.Path, []byte(next), 0600)

	case ModeStructured:
		// No backup: the file was created by us (or the user's file was written
		// before backups existed). It is ours to delete only if it still points at
		// the firewall.
		if host == "" || !strings.Contains(existing, host) {
			return out, nil
		}
		out.Configured = true
		out.Deleted = true
		if dryRun {
			return out, nil
		}
		return out, os.Remove(f.Path)

	default:
		next, changed := Remove(existing, m)
		if !changed {
			return out, nil
		}
		out.Configured = true
		if strings.TrimSpace(next) == "" {
			out.Deleted = true
			if dryRun {
				return out, nil
			}
			return out, os.Remove(f.Path)
		}
		out.Stripped = true
		if dryRun {
			return out, nil
		}
		return out, os.WriteFile(f.Path, []byte(next), 0600)
	}
}
