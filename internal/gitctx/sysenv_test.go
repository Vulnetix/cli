package gitctx

import (
	"runtime"
	"testing"
)

func TestCollectSystemInfo_NonNil(t *testing.T) {
	info := CollectSystemInfo()
	if info == nil {
		t.Fatal("expected non-nil SystemInfo")
	}
}

func TestCollectSystemInfo_OSArch(t *testing.T) {
	info := CollectSystemInfo()
	if info.OS != runtime.GOOS {
		t.Errorf("expected OS %q, got %q", runtime.GOOS, info.OS)
	}
	if info.Arch != runtime.GOARCH {
		t.Errorf("expected Arch %q, got %q", runtime.GOARCH, info.Arch)
	}
}

func TestCollectSystemInfo_Hostname(t *testing.T) {
	info := CollectSystemInfo()
	if info.Hostname == "" {
		t.Error("expected non-empty hostname")
	}
}

func TestCollectSystemInfo_Username(t *testing.T) {
	info := CollectSystemInfo()
	if info.Username == "" {
		t.Error("expected non-empty username")
	}
}

func TestCollectSystemInfo_Shell(t *testing.T) {
	info := CollectSystemInfo()
	// Shell may or may not be set, but the field exists
	_ = info.Shell
}

func TestStopIter_Error(t *testing.T) {
	s := &stopIter{}
	if s.Error() != "stop" {
		t.Errorf("expected 'stop', got %q", s.Error())
	}
}
