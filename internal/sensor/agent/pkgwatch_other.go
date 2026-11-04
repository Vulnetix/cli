//go:build !linux

package agent

import (
	"context"
	"time"
)

// watchPackageDBs has nothing to watch off Linux: the ticker reports.
func watchPackageDBs(context.Context, string, time.Duration, chan<- struct{}) {}
