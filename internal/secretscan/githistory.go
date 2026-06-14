package secretscan

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// zlibInflate is a small wrapper around compress/zlib for use in the
// loose-object fallback path. It returns an error rather than panicking on
// corrupt input.
func zlibInflate(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// treeForCommit returns the tree object for a given commit hash, walking
// the commit header as needed.
func treeForCommit(repo *git.Repository, hash plumbing.Hash) (*object.Tree, error) {
	c, err := repo.CommitObject(hash)
	if err != nil {
		return nil, err
	}
	return repo.TreeObject(c.TreeHash)
}

// GitHistoryOptions configures the git history scan.
type GitHistoryOptions struct {
	// MaxCommits caps how many commits are walked. Zero means no cap. The
	// walk is performed newest-first.
	MaxCommits int
	// MaxFileBytes caps the size of any single file extracted from history.
	// Files larger than this are skipped. Defaults to 4 MiB.
	MaxFileBytes int64
	// MaxFiles caps how many file versions are extracted in total. Zero
	// means no cap.
	MaxFiles int
}

// GitHistoryEntry is a single file version extracted from git history.
type GitHistoryEntry struct {
	// Key is the synthetic path that should be added to the secrets scan
	// input.file_contents map. Format: "__git_history__/<short-sha>/<path>".
	Key string
	// Value is the file contents as a string.
	Value string
	// CommitHash is the full commit hash the version was taken from.
	CommitHash string
	// FilePath is the file path inside the commit tree.
	FilePath string
	// IsDelete reports whether this entry represents the deletion of a file
	// (i.e. the commit removed it). We still emit a sentinel so the rule
	// can correlate, but Value is empty.
	IsDelete bool
}

// ScanGitHistory walks the git history of the repository rooted at repoRoot
// and returns a list of file versions suitable for the secrets scan input.
//
// The walk is breadth-first newest-first, bounded by opts. The function
// returns immediately with an empty slice (and a nil error) when repoRoot
// is not a git repository, or when the .git directory is unreadable —
// callers that want to treat "no history" as a fatal condition should
// inspect err separately.
func ScanGitHistory(repoRoot string, opts GitHistoryOptions) ([]GitHistoryEntry, error) {
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = 4 << 20
	}
	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, err
	}
	repo, err := git.PlainOpen(absRoot)
	if err != nil {
		// Not a git repository — quiet success, empty history.
		return nil, nil
	}
	head, err := repo.Head()
	if err != nil {
		return nil, nil
	}
	cIter, err := repo.Log(&git.LogOptions{From: head.Hash()})
	if err != nil {
		return nil, err
	}
	defer cIter.Close()

	seen := make(map[string]bool)
	var out []GitHistoryEntry
	commitCount := 0
	for {
		c, err := cIter.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		commitCount++
		if opts.MaxCommits > 0 && commitCount > opts.MaxCommits {
			break
		}
		// Diff against parent(s) so we only scan files that actually changed.
		// For merge commits with multiple parents, fall back to a full tree walk.
		parents := c.ParentHashes
		changed := map[string]changeKind{}
		if len(parents) == 0 {
			// Root commit: every file is "added".
			files, err := listTreeFiles(repo, c.TreeHash)
			if err != nil {
				continue
			}
			for _, p := range files {
				changed[p] = changeAdded
			}
		} else {
			// Resolve this commit's tree and each parent's tree, then diff
			// them via the lower-level plumbing/object API. go-git does not
			// expose Repository.Patch; the public path is object.DiffTree.
			currentTree, err := repo.TreeObject(c.TreeHash)
			if err != nil {
				continue
			}
			for _, ph := range parents {
				parentTree, err := treeForCommit(repo, ph)
				if err != nil {
					continue
				}
				changes, err := object.DiffTree(parentTree, currentTree)
				if err != nil {
					// Fall back to full tree walk for this parent.
					files, lerr := listTreeFiles(repo, c.TreeHash)
					if lerr != nil {
						continue
					}
					for _, p := range files {
						changed[p] = changeAdded
					}
					continue
				}
				for _, ch := range changes {
					action, aerr := ch.Action()
					var k changeKind
					switch aerr {
					case nil:
						// ok
					default:
						continue
					}
					switch action.String() {
					case "Insert":
						k = changeAdded
					case "Delete":
						k = changeDeleted
					case "Modify":
						k = changeModified
					default:
						k = changeModified
					}
					// ch.From / ch.To holds the tree entry; pull the path from
					// whichever side exists.
					name := ""
					if ch.From.Name != "" {
						name = ch.From.Name
					}
					if name == "" && ch.To.Name != "" {
						name = ch.To.Name
					}
					if name != "" {
						changed[name] = k
					}
				}
			}
		}

		// Stable iteration order so output is reproducible.
		paths := make([]string, 0, len(changed))
		for p := range changed {
			paths = append(paths, p)
		}
		sort.Strings(paths)

		shortSHA := c.Hash.String()
		if len(shortSHA) > 7 {
			shortSHA = shortSHA[:7]
		}
		for _, p := range paths {
			if opts.MaxFiles > 0 && len(out) >= opts.MaxFiles {
				return out, nil
			}
			kind := changed[p]
			entry := GitHistoryEntry{
				CommitHash: c.Hash.String(),
				FilePath:   p,
				IsDelete:   kind == changeDeleted,
			}
			// Dedupe identical (commit, path) tuples — root commit fallback
			// and merge commits can produce duplicates.
			dedupKey := c.Hash.String() + "\x00" + p + "\x00" + string(kind)
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true
			if kind == changeDeleted {
				entry.Key = PathGitHistoryPrefix + shortSHA + "/" + p
				entry.Value = ""
				out = append(out, entry)
				continue
			}
			// Look up the file in the commit's tree.
			f, err := fileFromTree(repo, c.TreeHash, p)
			if err != nil || f == nil {
				continue
			}
			if f.Size > opts.MaxFileBytes {
				continue
			}
			// Read the blob. For symlinks/submodules, skip — they cannot carry
			// credentials in the way rules expect.
			if f.Mode != filemode.Regular && f.Mode != filemode.Executable {
				continue
			}
			blob, err := repo.BlobObject(f.Hash)
			if err != nil {
				continue
			}
			reader, err := blob.Reader()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(io.LimitReader(reader, opts.MaxFileBytes+1))
			reader.Close()
			if err != nil {
				continue
			}
			if int64(len(data)) > opts.MaxFileBytes {
				continue
			}
			// Skip binary blobs — secrets in source code, not in compiled blobs.
			if IsBinary(data) {
				continue
			}
			entry.Key = PathGitHistoryPrefix + shortSHA + "/" + p
			entry.Value = string(data)
			out = append(out, entry)
		}
	}
	return out, nil
}

type changeKind string

const (
	changeAdded    changeKind = "added"
	changeModified changeKind = "modified"
	changeDeleted  changeKind = "deleted"
)

// listTreeFiles returns a flat list of regular file paths under treeHash.
func listTreeFiles(repo *git.Repository, treeHash plumbing.Hash) ([]string, error) {
	tree, err := repo.TreeObject(treeHash)
	if err != nil {
		return nil, err
	}
	var out []string
	err = tree.Files().ForEach(func(f *object.File) error {
		if f.Mode == filemode.Regular || f.Mode == filemode.Executable {
			out = append(out, f.Name)
		}
		return nil
	})
	return out, err
}

// fileFromTree returns the tree entry for path under treeHash, or nil if the
// path is not present (e.g. file moved away between commits).
func fileFromTree(repo *git.Repository, treeHash plumbing.Hash, path string) (*object.File, error) {
	tree, err := repo.TreeObject(treeHash)
	if err != nil {
		return nil, err
	}
	return tree.File(path)
}

// ScanLooseGitObjects is a fallback for the case where the repository's pack
// files are corrupt or unavailable: walk the loose objects in .git/objects
// and decompress any that are blobs. This is slower than ScanGitHistory but
// does not depend on the go-git walker.
//
// The returned entries use the synthetic path "__git_history__/loose/<sha>".
// The file path inside the commit/tree cannot be reconstructed for a loose
// blob on its own, so we surface the blob as a single best-effort extraction.
func ScanLooseGitObjects(repoRoot string, maxBytes int64) ([]GitHistoryEntry, error) {
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, err
	}
	objectsDir := filepath.Join(absRoot, ".git", "objects")
	info, err := os.Stat(objectsDir)
	if err != nil || !info.IsDir() {
		return nil, nil
	}
	entries, err := os.ReadDir(objectsDir)
	if err != nil {
		return nil, err
	}
	var out []GitHistoryEntry
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) != 2 {
			continue
		}
		shard := e.Name()
		shardDir := filepath.Join(objectsDir, shard)
		files, err := os.ReadDir(shardDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			full := filepath.Join(shardDir, f.Name())
			sha := shard + f.Name()
			entry, ok := decompressIfBlob(sha, full, maxBytes)
			if ok {
				out = append(out, entry)
			}
		}
	}
	return out, nil
}

func decompressIfBlob(sha, path string, maxBytes int64) (GitHistoryEntry, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return GitHistoryEntry{}, false
	}
	// Loose object format: "blob <size>\0<payload>". The header is plain text.
	// We try to detect via the header — anything starting with "blob " is a blob.
	// We do not have zlib available here without an import; loose objects are
	// stored with deflate compression, so we skip those that don't decode quickly.
	// For the loose-object fallback we rely on go-git's blob reading above;
	// this function is a best-effort scanner for objects that go-git skipped.
	if len(data) < 8 {
		return GitHistoryEntry{}, false
	}
	// Cheap sniff: a deflate stream begins with 0x78 0x01/0x9c/0xda.
	if data[0] != 0x78 {
		return GitHistoryEntry{}, false
	}
	payload, err := zlibInflate(data)
	if err != nil {
		return GitHistoryEntry{}, false
	}
	if !strings.HasPrefix(string(payload[:min(len(payload), 8)]), "blob ") {
		return GitHistoryEntry{}, false
	}
	// Strip header.
	idx := indexByte(payload, 0)
	if idx < 0 {
		return GitHistoryEntry{}, false
	}
	body := payload[idx+1:]
	if int64(len(body)) > maxBytes {
		return GitHistoryEntry{}, false
	}
	if IsBinary(body) {
		return GitHistoryEntry{}, false
	}
	// Verify SHA1.
	h := sha1.New()
	h.Write([]byte("blob "))
	h.Write([]byte(fmt.Sprintf("%d\x00", len(body))))
	h.Write(body)
	sum := hex.EncodeToString(h.Sum(nil))
	if sum != sha {
		return GitHistoryEntry{}, false
	}
	short := sha
	if len(short) > 7 {
		short = short[:7]
	}
	return GitHistoryEntry{
		Key:        PathGitHistoryPrefix + "loose/" + short,
		Value:      string(body),
		CommitHash: sha,
		FilePath:   "(loose blob)",
	}, true
}

// indexByte is a tiny helper to avoid importing bytes for a single call.
func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
