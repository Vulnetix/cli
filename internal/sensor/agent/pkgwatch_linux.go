//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// pkgDBDirs are the directories whose change means a package was installed,
// upgraded or removed: the dpkg status file's directory, the apk database, the
// pacman local database and the rpm databases. Watching the directory, not the
// file, survives the rename every package manager writes its database with.
var pkgDBDirs = []string{
	"var/lib/dpkg",
	"lib/apk/db",
	"var/lib/apk/db",
	"var/lib/pacman/local",
	"var/lib/rpm",
	"usr/lib/sysimage/rpm",
}

// watchPackageDBs sends on changed once the package databases under root have
// been quiet for debounce after a change, so one upgrade of many packages is
// one report. It returns when ctx ends or no directory can be watched.
func watchPackageDBs(ctx context.Context, root string, debounce time.Duration, changed chan<- struct{}) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(fd) }()
	watched := 0
	for _, rel := range pkgDBDirs {
		dir := filepath.Join(root, rel)
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			continue
		}
		mask := uint32(unix.IN_CLOSE_WRITE | unix.IN_MOVED_TO | unix.IN_CREATE | unix.IN_DELETE)
		if _, err := unix.InotifyAddWatch(fd, dir, mask); err == nil {
			watched++
		}
	}
	if watched == 0 {
		return
	}

	buf := make([]byte, 64*1024)
	var due time.Time
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			// Drain whatever arrived; any event restarts the quiet period.
			for {
				n, err := unix.Read(fd, buf)
				if n <= 0 || err != nil {
					break
				}
				due = now.Add(debounce)
			}
			if !due.IsZero() && now.After(due) {
				due = time.Time{}
				select {
				case changed <- struct{}{}:
				default: // a report is already waiting
				}
			}
		}
	}
}
