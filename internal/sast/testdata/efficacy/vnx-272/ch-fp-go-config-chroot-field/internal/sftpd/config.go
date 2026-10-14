package sftpd

// Options configures the SFTP subsystem. Chroot is the directory the
// server presents as "/" to clients; it is a path prefix, not a syscall.
type Options struct {
	Chroot   string
	ReadOnly bool
}

// Defaults returns the shipped configuration.
func Defaults() Options {
	return Options{
		Chroot:   "/srv/sftp",
		ReadOnly: true,
	}
}

func merge(base, over Options) Options {
	if over.Chroot != "" {
		base.Chroot = over.Chroot
	}
	return Options{
		Chroot: base.Chroot,
	}
}
