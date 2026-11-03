// Package addongate recognises the platform saying "this needs a paid add-on".
//
// The site answers a gated write or device route with a real HTTP 402 and a
// JSON body naming the add-on, and (for a read, or an older deploy) with HTTP
// 200 and a soft marker `planLocked: true`. Neither is a success: a client
// that parses the 200 as an answer drops the events it just "sent" and applies
// an empty config. Callers turn both into one *Error, keep what they hold and
// back off.
package addongate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// BillingURL is where an add-on is bought.
const BillingURL = "https://www.vulnetix.com/resolve/billing#addons"

// Error is a denial for a missing add-on (or a plan floor).
type Error struct {
	Method, Path string
	Status       int
	// Addon is AddonSubscription.kind from the body: soc_intelligence or
	// package_firewall. Empty when the site did not name one.
	Addon string
	// Soft is true when the denial arrived as HTTP 200 with planLocked.
	Soft bool
}

// DisplayName is the name a person knows the add-on by.
func DisplayName(kind string) string {
	switch kind {
	case "soc_intelligence":
		return "SOC Intelligence"
	case "package_firewall":
		return "Package Firewall"
	case "":
		return "required"
	}

	return kind
}

func (e *Error) Error() string {
	subject := "an add-on is required"
	if e.Addon != "" {
		subject = fmt.Sprintf("the %s add-on is required", DisplayName(e.Addon))
	}
	how := fmt.Sprintf("HTTP %d", e.Status)
	if e.Soft {
		how = fmt.Sprintf("HTTP %d planLocked", e.Status)
	}

	return fmt.Sprintf("%s %s: %s: %s (add it at %s)", e.Method, e.Path, how, subject, BillingURL)
}

// Is reports whether err is, or wraps, an add-on denial.
func Is(err error) bool {
	var e *Error

	return errors.As(err, &e)
}

// FromResponse returns the denial a response carries, or nil. A 402 is always
// one; a 2xx is one when its JSON body has planLocked true. Any other status,
// and any body that is not that marker, is not a denial.
func FromResponse(method, path string, status int, body []byte) *Error {
	soft := status/100 == 2
	if status != http.StatusPaymentRequired && !soft {
		return nil
	}
	var m struct {
		PlanLocked   bool   `json:"planLocked"`
		Addon        string `json:"addon"`
		Entitlements struct {
			Addon string `json:"addon"`
		} `json:"_entitlements"`
	}
	parsed := json.Unmarshal(body, &m) == nil
	if soft && (!parsed || !m.PlanLocked) {
		return nil
	}
	addon := m.Addon
	if addon == "" {
		addon = m.Entitlements.Addon
	}

	return &Error{Method: method, Path: path, Status: status, Addon: addon, Soft: soft}
}
