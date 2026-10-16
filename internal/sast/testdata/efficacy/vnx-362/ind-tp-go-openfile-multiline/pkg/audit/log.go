package audit

import "os"

func openAuditLog(logPath string) (*os.File, error) {
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
~>		return os.OpenFile(logPath,
			os.O_WRONLY|os.O_CREATE|os.O_APPEND,
			0o640)
	}
	return os.Open(logPath)
}
