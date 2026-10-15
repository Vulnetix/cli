package shard

import (
	"math/rand"
	"path/filepath"
)

func RandomRootPath(roots []string) string {
	rootPath := roots[rand.Intn(len(roots))]
	return filepath.Clean(rootPath)
}

func HotPartition(n int) int {
	hotPart := rand.Intn(n)
	return hotPart
}

func SpinnerFrame(frames []string) string {
	return frames[rand.Intn(len(frames))]
}
