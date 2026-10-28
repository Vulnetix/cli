//go:build !unix

package execwatch

// inode is not available here; rotation is not detected, which only matters
// on the Linux hosts the sensor ships for.
func inode(string) uint64 { return 0 }
