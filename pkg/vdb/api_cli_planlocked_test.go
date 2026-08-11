package vdb

import (
	"errors"
	"strings"
	"testing"
)

// A plan-locked endpoint answers 200 with a marker body rather than the usual
// {meta, data} envelope. To a decoder that only knows the envelope, that is a
// successful response carrying no data — so the CLI would print "applied" for a
// write the server refused, and the operator would find out weeks later that
// the rule they thought they had was never stored.
//
// These tests exist to keep that failure impossible.

func TestPlanLockedBodyIsAnError(t *testing.T) {
	body := []byte(`{"planLocked":true,"feature":"ai-firewall-guardrails","requiredPlan":"teams","upgrade":true}`)

	_, err := decodeCliResponse[map[string]any](body)
	if err == nil {
		t.Fatal("a plan-locked body must not decode as success")
	}

	var locked *PlanLockedError
	if !errors.As(err, &locked) {
		t.Fatalf("error type = %T, want *PlanLockedError so a caller can tell this from a bad request", err)
	}
	if locked.Feature != "ai-firewall-guardrails" || locked.RequiredPlan != "teams" {
		t.Errorf("feature/plan = %q/%q, want ai-firewall-guardrails/teams", locked.Feature, locked.RequiredPlan)
	}
	// The message has to name the plan: "forbidden" sends somebody hunting
	// through their config for a mistake they did not make.
	if msg := err.Error(); !strings.Contains(msg, "teams") || !strings.Contains(msg, "nothing was changed") {
		t.Errorf("message = %q, should name the plan and say nothing changed", msg)
	}
}

func TestOrdinaryResponseStillDecodes(t *testing.T) {
	body := []byte(`{"meta":{"tier":"pro","requestId":"r1"},"data":{"uuid":"g1"}}`)

	resp, err := decodeCliResponse[map[string]any](body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Meta.Tier != "pro" {
		t.Errorf("Tier = %q, want pro", resp.Meta.Tier)
	}
	if resp.Data["uuid"] != "g1" {
		t.Errorf("Data = %+v, want the guardrail uuid", resp.Data)
	}
}

func TestPlanLockedFalseIsNotLocked(t *testing.T) {
	// The marker is only a marker when it says so. A payload that happens to
	// carry the field set false is an ordinary response.
	body := []byte(`{"meta":{"tier":"teams"},"data":{"planLocked":false}}`)

	if _, err := decodeCliResponse[map[string]any](body); err != nil {
		t.Fatalf("planLocked:false must decode normally, got %v", err)
	}
}
