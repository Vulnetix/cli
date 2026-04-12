package license

import "testing"

func TestClassifyLicenseText(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{"MIT", "MIT License\n\nPermission is hereby granted, free of charge", "MIT"},
		{"Apache-2.0", "Apache License\nVersion 2.0, January 2004", "Apache-2.0"},
		{"BSD-3", "Redistribution and use in source and binary forms\nRedistributions of source code\nRedistributions in binary form\nNeither the name", "BSD-3-Clause"},
		{"BSD-2", "Redistribution and use in source and binary forms\nRedistributions of source code\nRedistributions in binary form", "BSD-2-Clause"},
		{"GPL-3", "GNU GENERAL PUBLIC LICENSE\nVersion 3", "GPL-3.0-only"},
		{"GPL-2", "GNU GENERAL PUBLIC LICENSE\nVersion 2", "GPL-2.0-only"},
		{"LGPL-2.1", "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1", "LGPL-2.1-only"},
		{"AGPL-3", "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3", "AGPL-3.0-only"},
		{"MPL-2.0", "Mozilla Public License Version 2.0", "MPL-2.0"},
		{"ISC", "ISC License\n\nPermission to use, copy, modify, and/or distribute", "ISC"},
		{"Unlicense", "This is free and unencumbered software released into the public domain", "Unlicense"},
		{"CC0", "CC0 1.0 Universal", "CC0-1.0"},
		{"empty", "", ""},
		{"random", "This is just some random text", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyLicenseText(tt.text)
			if got != tt.want {
				t.Errorf("ClassifyLicenseText(%q...) = %q, want %q", tt.text[:min(len(tt.text), 40)], got, tt.want)
			}
		})
	}
}
