package upload

import "fmt"

// ChunkedUpload handles large file uploads by splitting into chunks
func (c *Client) ChunkedUpload(fileName string, data []byte, contentType, format string) (*FinalizeResponse, error) {
	return c.ChunkedUploadWithProgress(fileName, data, contentType, format, nil)
}

// ChunkedUploadWithProgress handles large file uploads by splitting into chunks
// and reporting progress after session initiation, each uploaded chunk, and
// finalization.
func (c *Client) ChunkedUploadWithProgress(fileName string, data []byte, contentType, format string, progress ProgressFunc) (*FinalizeResponse, error) {
	fileSize := len(data)
	chunkSize := DefaultChunkSize
	totalChunks := (fileSize + chunkSize - 1) / chunkSize
	totalSteps := totalChunks + 2

	// Initiate session
	if progress != nil {
		progress(0, totalSteps, "Initiating chunked upload session")
	}
	session, err := c.InitiateSession(fileName, fileSize, contentType, totalChunks, chunkSize, format)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate chunked upload: %w", err)
	}
	if progress != nil {
		progress(1, totalSteps, "Uploading chunks")
	}

	// Upload each chunk
	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > fileSize {
			end = fileSize
		}

		chunk := data[start:end]
		if _, err := c.UploadChunk(session.UploadSessionID, i+1, chunk); err != nil {
			return nil, fmt.Errorf("failed to upload chunk %d/%d: %w", i+1, totalChunks, err)
		}
		if progress != nil {
			progress(i+2, totalSteps, fmt.Sprintf("Uploaded chunk %d/%d", i+1, totalChunks))
		}
	}

	// Finalize
	if progress != nil {
		progress(totalSteps-1, totalSteps, "Finalizing upload")
	}
	result, err := c.FinalizeUpload(session.UploadSessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize chunked upload: %w", err)
	}
	if progress != nil {
		progress(totalSteps, totalSteps, "Upload finalized")
	}

	return result, nil
}
