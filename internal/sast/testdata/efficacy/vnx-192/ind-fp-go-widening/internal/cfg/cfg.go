package cfg

import (
	"os"
	"strconv"
	"time"
)

func Timeout() time.Duration {
	secs, err := strconv.Atoi(os.Getenv("TIMEOUT_SECONDS"))
	if err != nil {
		return 30 * time.Second
	}
	return time.Duration(int64(secs)) * time.Second
}

func Ratio() float64 {
	n, _ := strconv.Atoi(os.Getenv("RATIO"))
	return float64(n) / 100
}
