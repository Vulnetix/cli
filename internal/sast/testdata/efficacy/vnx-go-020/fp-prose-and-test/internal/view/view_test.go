package view

import (
	"html/template"
	"testing"
)

func TestRaw(t *testing.T) {
	in := "<b>x</b>"
	if got := template.HTML(in); got != "<b>x</b>" {
		t.Fatal(got)
	}
}
