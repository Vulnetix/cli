package upload

import "fmt"

// ChunkedUpload handles large file uploads by splitting into chunks
func (c *Client) ChunkedUpload(fileName string, data []byte, contentType, format string) (*FinalizeResponse, error) {
	fileSize := len(data)
	chunkSize := DefaultChunkSize
	totalChunks := (fileSize + chunkSize - 1) / chunkSize

	// Initiate session
	session, err := c.InitiateSession(fileName, fileSize, contentType, totalChunks, chunkSize)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate chunked upload: %w", err)
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
	}

	// Finalize
	result, err := c.FinalizeUpload(session.UploadSessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize chunked upload: %w", err)
	}

	return result, nil
}
