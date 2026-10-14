package unpack

import (
	"archive/tar"
	"os"
)

func restoreOwner(target string, hdr *tar.Header) error {
~>	if err := os.Lchown(target, hdr.Uid, hdr.Gid); err != nil {
		return err
	}
~>	return os.Chown(target, hdr.Uid, hdr.Gid)
}
