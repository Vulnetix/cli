package agent

import "testing"

func TestSweepRealWorldSpellings(t *testing.T) {
	cases := []struct{ cmd string; wantPkg string }{
		{"npm install --save axios", "axios"},
		{"npm i axios --save-dev", "axios"},
		{"yarn add -D typescript", "typescript"},
		{"pnpm i -D vitest", "vitest"},
		{`pip install "requests>=2,<3"`, "requests"},
		{"python -m pip install requests", "requests"},
		{"python3 -m pip install requests", "requests"},
		{"npm i axios \\\n  lodash", "axios"},
		{"go install github.com/x/y@latest", "github.com/x/y"},
		{"npm --prefix ./web install axios", "axios"},
		{"yarn --cwd web add axios", "axios"},
		{"npm i @types/node -D", "@types/node"},
		{"poetry add 'requests@^2.31'", "requests"},
		{"uv add --dev pytest", "pytest"},
	}
	for _, tc := range cases {
		got := ParseInstallCommand(tc.cmd)
		if len(got) == 0 {
			t.Errorf("MISS  %-40q found nothing, want %s", tc.cmd, tc.wantPkg)
			continue
		}
		if got[0].Name != tc.wantPkg {
			t.Errorf("WRONG %-40q got %q, want %q", tc.cmd, got[0].Name, tc.wantPkg)
		}
	}
}

func TestSweepMustStaySilent(t *testing.T) {
	for _, cmd := range []string{
		"cargo install ripgrep", "npm install -g typescript",
		"apt-get install -y curl", "brew install jq",
		"npx --yes create-react-app my-app", "pnpm dlx shadcn init",
		"npm exec -- eslint .", "go run ./cmd/x",
	} {
		if got := ParseInstallCommand(cmd); len(got) > 0 {
			t.Errorf("NOISE %-40q produced %+v", cmd, got)
		}
	}
}
