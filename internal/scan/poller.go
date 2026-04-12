package scan

import (
	"context"
	"sync"
	"time"

	"github.com/vulnetix/cli/pkg/vdb"
)

// PollEngine handles concurrent polling for scan results.
type PollEngine struct {
	Client     *vdb.Client
	Interval   time.Duration   // polling interval (default 5s)
	OnProgress func(*ScanTask) // callback for UI updates (called from goroutines)
}

// PollAll polls all tasks with a scan ID until they are complete or errored.
// Tasks without a scan ID are skipped.
func (p *PollEngine) PollAll(ctx context.Context, tasks []*ScanTask) {
	interval := p.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}

	var wg sync.WaitGroup

	for _, task := range tasks {
		if task.ScanID == "" || task.Status == "error" {
			continue
		}

		wg.Add(1)
		go func(t *ScanTask) {
			defer wg.Done()
			p.pollOne(ctx, t, interval)
		}(task)
	}

	wg.Wait()
}

func (p *PollEngine) pollOne(ctx context.Context, t *ScanTask, interval time.Duration) {
	t.Status = "polling"
	t.PollStart = time.Now()
	if p.OnProgress != nil {
		p.OnProgress(t)
	}

	for {
		select {
		case <-ctx.Done():
			t.Status = "error"
			t.Error = ctx.Err()
			t.PollEnd = time.Now()
			if p.OnProgress != nil {
				p.OnProgress(t)
			}
			return
		default:
		}

		result, err := p.Client.V2ScanStatus(t.ScanID)
		if err != nil {
			t.Status = "error"
			t.Error = err
			t.PollEnd = time.Now()
			t.RawResult = nil
			if p.OnProgress != nil {
				p.OnProgress(t)
			}
			return
		}

		status, _ := result["status"].(string)

		switch status {
		case "complete", "completed":
			t.Status = "complete"
			t.PollEnd = time.Now()
			t.RawResult = result
			t.Vulns = ParseVulnsFromScanResult(result, t.File.RelPath)
			if p.OnProgress != nil {
				p.OnProgress(t)
			}
			return

		case "error", "failed":
			t.Status = "error"
			t.PollEnd = time.Now()
			t.RawResult = result
			errMsg := "scan failed"
			if msg, ok := result["error"].(string); ok {
				errMsg = msg
			}
			t.Error = &ScanError{Message: errMsg}
			if p.OnProgress != nil {
				p.OnProgress(t)
			}
			return

		default:
			// Still processing — update progress and wait
			if p.OnProgress != nil {
				p.OnProgress(t)
			}

			select {
			case <-ctx.Done():
				t.Status = "error"
				t.Error = ctx.Err()
				t.PollEnd = time.Now()
				if p.OnProgress != nil {
					p.OnProgress(t)
				}
				return
			case <-time.After(interval):
			}
		}
	}
}

// ScanError represents a scan-side error returned by the API.
type ScanError struct {
	Message string
}

func (e *ScanError) Error() string {
	return e.Message
}
