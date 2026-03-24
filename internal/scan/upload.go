package scan

import (
	"context"
	"sync"
	"time"

	"github.com/vulnetix/cli/internal/gitctx"
	"github.com/vulnetix/cli/internal/vdb"
)

// UploadEngine handles concurrent file uploads to the VDB API.
type UploadEngine struct {
	Client      *vdb.Client
	Concurrency int                // max concurrent uploads (default 5)
	OnProgress  func(*ScanTask)    // callback for UI updates (called from goroutines)
	GitContext  *gitctx.GitContext  // shared git context (collected once, may be nil)
	RepoRoot   string              // git repo root path (may be empty)
}

// UploadAll uploads all detected files concurrently using a bounded semaphore.
// Returns a ScanTask for each file with status "uploaded" or "error".
func (e *UploadEngine) UploadAll(ctx context.Context, files []DetectedFile) []*ScanTask {
	concurrency := e.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	if concurrency > len(files) {
		concurrency = len(files)
	}

	tasks := make([]*ScanTask, len(files))
	for i, f := range files {
		tasks[i] = &ScanTask{
			File:   f,
			Status: "queued",
		}
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, task := range tasks {
		if ctx.Err() != nil {
			// Context cancelled — mark remaining as error
			for j := i; j < len(tasks); j++ {
				tasks[j].Status = "error"
				tasks[j].Error = ctx.Err()
				if e.OnProgress != nil {
					e.OnProgress(tasks[j])
				}
			}
			break
		}

		wg.Add(1)
		sem <- struct{}{} // acquire semaphore

		go func(t *ScanTask) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore

			e.uploadOne(ctx, t)
		}(task)
	}

	wg.Wait()
	return tasks
}

func (e *UploadEngine) uploadOne(ctx context.Context, t *ScanTask) {
	t.Status = "uploading"
	t.UploadStart = time.Now()
	if e.OnProgress != nil {
		e.OnProgress(t)
	}

	// Check context before making the API call
	select {
	case <-ctx.Done():
		t.Status = "error"
		t.Error = ctx.Err()
		t.UploadEnd = time.Now()
		if e.OnProgress != nil {
			e.OnProgress(t)
		}
		return
	default:
	}

	var result map[string]interface{}
	var err error

	switch t.File.FileType {
	case FileTypeManifest:
		payload, _ := BuildPayload(t.File, e.GitContext, e.RepoRoot)
		result, err = e.Client.V2ScanManifest(t.File.Path, t.File.ManifestInfo.Type, t.File.ManifestInfo.Ecosystem, payload)
	case FileTypeSPDX:
		payload, _ := BuildPayload(t.File, e.GitContext, e.RepoRoot)
		result, err = e.Client.V2ScanSPDX(t.File.Path, payload)
	case FileTypeCycloneDX:
		payload, _ := BuildPayload(t.File, e.GitContext, e.RepoRoot)
		result, err = e.Client.V2ScanCycloneDX(t.File.Path, payload)
	default:
		t.Status = "error"
		t.Error = &UnsupportedFileError{Path: t.File.Path}
		t.UploadEnd = time.Now()
		if e.OnProgress != nil {
			e.OnProgress(t)
		}
		return
	}

	t.UploadEnd = time.Now()

	if err != nil {
		t.Status = "error"
		t.Error = err
		if e.OnProgress != nil {
			e.OnProgress(t)
		}
		return
	}

	// Extract scan ID from response
	if id, ok := result["scanId"].(string); ok {
		t.ScanID = id
	}

	t.Status = "uploaded"
	t.RawResult = result
	if e.OnProgress != nil {
		e.OnProgress(t)
	}
}

// UnsupportedFileError is returned when a file type is not supported for upload.
type UnsupportedFileError struct {
	Path string
}

func (e *UnsupportedFileError) Error() string {
	return "unsupported file type: " + e.Path
}
