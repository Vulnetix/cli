package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTask(t *testing.T) {
	tests := []struct {
		name        string
		task        string
		expectedErr string
	}{
		{name: "Valid info task", task: "info", expectedErr: ""},
		{name: "Valid triage task", task: "triage", expectedErr: ""},
		{name: "Invalid task", task: "invalid", expectedErr: "unsupported task"},
		{name: "Empty task", task: "", expectedErr: ""}, // Default to info, no error
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateTask(tt.task) // ValidateTask returns (TaskType, error)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}
