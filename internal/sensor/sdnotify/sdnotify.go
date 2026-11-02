// Package sdnotify is a minimal sd_notify(3): it tells systemd the sensor is
// ready and pings the watchdog, over the datagram socket systemd names in
// NOTIFY_SOCKET. Outside a Type=notify unit every call is a no-op.
package sdnotify

import (
	"net"
	"os"
	"strconv"
	"time"
)

// Notify sends state (e.g. "READY=1") to systemd. It reports false, nil
// when NOTIFY_SOCKET is unset.
func Notify(state string) (bool, error) {
	return NotifyTo(os.Getenv("NOTIFY_SOCKET"), state)
}

// NotifyTo sends state to the socket at path. A leading "@" is an abstract
// socket.
func NotifyTo(path, state string) (bool, error) {
	if path == "" {
		return false, nil
	}
	if path[0] == '@' {
		path = "\x00" + path[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, err
	}

	return true, nil
}

// WatchdogInterval is the watchdog timeout systemd set for this process
// (WATCHDOG_USEC, checked against WATCHDOG_PID), or 0 when there is none.
func WatchdogInterval() time.Duration {
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0
	}
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}

	return time.Duration(usec) * time.Microsecond
}
