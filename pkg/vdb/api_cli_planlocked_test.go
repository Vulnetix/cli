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

// The v2 GET path had the same hole for longer, and more quietly: doV2Get
// unmarshalled the marker into a plain map and handed it back as data, so
// `vulnetix vdb countermeasures get CVE-…` on a community key printed
// {"planLocked":true,…} as though that were the answer, and exited 0. A script
// checking the exit code saw a success; an operator saw JSON.
//
// decodePlanLocked is what doV2Get now runs first. These assert the two halves
// of that contract on the exact bodies the defence endpoints return.

func TestV2PlanLockedMarkerDecodes(t *testing.T) {
	body := []byte(`{"planLocked":true,"feature":"countermeasures","requiredPlan":"pro","upgrade":true,` +
		`"error":"Pro subscription required to download a defence rule",` +
		`"_entitlements":{"plan":"community","gated":[{"feature":"countermeasures","requiredPlan":"pro"}]}}`)

	locked, ok := decodePlanLocked(body)
	if !ok {
		t.Fatal("the defence archive marker must be recognised as plan-locked")
	}
	if locked.Feature != "countermeasures" || locked.RequiredPlan != "pro" {
		t.Errorf("feature/plan = %q/%q, want countermeasures/pro", locked.Feature, locked.RequiredPlan)
	}
	if msg := locked.Error(); !strings.Contains(msg, "pro") {
		t.Errorf("message = %q, should name the plan the caller needs", msg)
	}
}

func TestV2FieldGatedResponseIsNotPlanLocked(t *testing.T) {
	// A field-gated 200 is NOT the marker. The catalogue endpoints null the
	// rule bodies and attach _entitlements while keeping count and total, and
	// that response must reach the caller: the counts are the part every tier
	// is entitled to. Treating it as an error would withhold the warning.
	body := []byte(`{"identifier":"CVE-2021-44228","count":3,"total":3,` +
		`"byKind":{"SIGMA":2,"YARA":1},` +
		`"countermeasures":null,` +
		`"_entitlements":{"plan":"community","gated":[{"feature":"countermeasures","requiredPlan":"pro"}]}}`)

	if _, ok := decodePlanLocked(body); ok {
		t.Fatal("a field-gated response must not be treated as plan-locked; the counts are still owed to the caller")
	}
}
