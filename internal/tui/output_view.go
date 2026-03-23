package tui

import (
	"os"

	"github.com/vulnetix/cli/internal/cdx"
	"github.com/vulnetix/cli/internal/scan"
)

func saveOutput(tasks []*scan.ScanTask, format, path string) error {
	specVersion, isRaw := cdx.NormalizeFormat(format)

	if isRaw {
		return saveRawJSON(tasks, path)
	}
	return saveCycloneDX(tasks, specVersion, path)
}

func saveCycloneDX(tasks []*scan.ScanTask, specVersion, path string) error {
	bom := cdx.BuildFromScanTasks(tasks, specVersion)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return bom.WriteJSON(f)
}

func saveRawJSON(tasks []*scan.ScanTask, path string) error {
	// Collect all raw results
	results := make(map[string]interface{})
	for _, t := range tasks {
		if t.RawResult != nil {
			key := t.File.RelPath
			if key == "" {
				key = t.ScanID
			}
			results[key] = t.RawResult
		}
	}

	bom := struct {
		Results map[string]interface{} `json:"results"`
	}{Results: results}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := jsonEncoder(f)
	return enc.Encode(bom)
}
