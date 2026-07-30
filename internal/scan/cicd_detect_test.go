package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetectManifestCICDCoverage pins the classification of pipeline-as-code and
// shell files. Each entry is a path relative to a temp root plus the manifest type
// it must resolve to; "" means the file must not be detected as a manifest at all.
func TestDetectManifestCICDCoverage(t *testing.T) {
	cases := []struct {
		path     string
		body     string
		wantType string
		wantEco  string
	}{
		// GitHub Actions and the forks that reuse its schema.
		{".github/workflows/ci.yml", "on: push\njobs: {}\n", "github-actions.yml", "github-actions"},
		{".gitea/workflows/build.yaml", "on: push\njobs: {}\n", "github-actions.yml", "github-actions"},
		{".forgejo/workflows/build.yml", "on: push\njobs: {}\n", "github-actions.yml", "github-actions"},
		{".github/actions/setup/action.yml", "runs:\n  using: composite\n", "github-actions.yml", "github-actions"},
		{"tools/publish/action.yaml", "runs:\n  using: composite\n", "github-actions.yml", "github-actions"},

		// Root-level pipeline files by exact name.
		{".gitlab-ci.yml", "stages: [build]\n", "ci-pipeline", "ci"},
		{"azure-pipelines.yml", "steps: []\n", "ci-pipeline", "ci"},
		{"bitbucket-pipelines.yaml", "pipelines: {}\n", "ci-pipeline", "ci"},
		{".build.yml", "image: alpine\ntasks: []\n", "ci-pipeline", "ci"},
		{"Taskfile.yml", "version: '3'\ntasks: {}\n", "ci-pipeline", "ci"},
		{"Jenkinsfile", "pipeline { }\n", "Jenkinsfile", "ci"},
		{"Earthfile", "VERSION 0.8\nbuild:\n  RUN apt-get install -y curl\n", "Dockerfile", "ci"},

		// Pipeline files found by directory.
		{".circleci/config.yml", "version: 2.1\njobs: {}\n", "ci-pipeline", "ci"},
		{".buildkite/pipeline.yml", "steps: []\n", "ci-pipeline", "ci"},
		{".tekton/task.yaml", "spec:\n  steps: []\n", "ci-pipeline", "ci"},
		{"bamboo-specs/plan.yaml", "version: 2\n", "ci-pipeline", "ci"},
		{".zuul.d/jobs.yaml", "- job:\n    name: build\n", "ci-pipeline", "ci"},
		{".devcontainer/devcontainer.json", `{"image":"x"}`, "ci-pipeline", "ci"},
		{".gitlab/ci/security.yml", "include: []\n", "ci-pipeline", "ci"},

		// Pipeline files found by name suffix outside a CI directory.
		{"deploy/security.gitlab-ci.yml", "stages: []\n", "ci-pipeline", "ci"},
		{"infra/release-pipeline.yaml", "jobs: []\n", "ci-pipeline", "ci"},

		// Shell and recipe files.
		{"scripts/install.sh", "#!/bin/bash\napt-get install -y curl\n", "shell-script", "shell"},
		{"scripts/setup.ps1", "choco install gh\n", "shell-script", "shell"},
		{"Makefile", "deps:\n\tgo install example.com/tool@v1.2.3\n", "shell-script", "shell"},
		{"justfile", "deps:\n\tcargo install just\n", "shell-script", "shell"},
		{"scripts/bootstrap", "#!/usr/bin/env bash\npip install requests\n", "shell-script", "shell"},

		// A Kubernetes manifest inside a CI directory keeps its own, more specific
		// classification — the CI path rule must not shadow it.
		{"ci/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\n", "kubernetes.yaml", "kubernetes"},
		// Compose files likewise.
		{"ci/stack.yml", "services:\n  web:\n    image: nginx:1.27\n", "compose.yaml", "docker"},

		// Files that must stay undetected.
		{"docs/notes.yaml", "title: hello\n", "", ""},
		{"scripts/README", "not a script\n", "", ""},
	}

	root := t.TempDir()
	for _, tc := range cases {
		full := filepath.Join(root, filepath.FromSlash(tc.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(tc.body), 0o644); err != nil {
			t.Fatal(err)
		}

		info, ok := DetectManifest(full)
		if tc.wantType == "" {
			if ok {
				t.Errorf("%s: detected as %+v, want no detection", tc.path, info)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: not detected, want type %q", tc.path, tc.wantType)
			continue
		}
		if info.Type != tc.wantType || info.Ecosystem != tc.wantEco {
			t.Errorf("%s: type=%q ecosystem=%q, want type=%q ecosystem=%q",
				tc.path, info.Type, info.Ecosystem, tc.wantType, tc.wantEco)
		}
		if !SupportedManifestTypes[info.Type] {
			t.Errorf("%s: type %q has no parser registered", tc.path, info.Type)
		}
	}
}

// TestDetectManifestCICDVendorDSLs covers the CI systems whose pipeline files are
// not YAML: TeamCity/Space Kotlin DSL, Jenkins Groovy libraries, and the
// hosting-platform build configs.
func TestDetectManifestCICDVendorDSLs(t *testing.T) {
	cases := []struct {
		path     string
		body     string
		wantType string
	}{
		{".teamcity/settings.kts", "script { scriptContent = \"apt-get install -y curl\" }\n", "ci-pipeline"},
		{".space.kts", "job(\"build\") { container(\"alpine\") { shellScript { content = \"apk add jq\" } } }\n", "ci-pipeline"},
		{".jenkins/shared.groovy", "sh 'pip install requests==2.32.0'\n", "ci-pipeline"},
		{"vercel.json", `{"installCommand":"pnpm add zod@3.23.8"}`, "ci-pipeline"},
		{"netlify.toml", "[build]\n  command = \"npm install -g typescript\"\n", "ci-pipeline"},
		{"heroku.yml", "build:\n  docker:\n    web: Dockerfile\n", "ci-pipeline"},
		{"shippable.yml", "build:\n  ci:\n    - apt-get install -y jq\n", "ci-pipeline"},
		// A Kotlin or Groovy file outside a CI directory is ordinary source code.
		{"src/main/Build.kts", "val x = 1\n", ""},
		{"src/main/Util.groovy", "def x = 1\n", ""},
	}

	root := t.TempDir()
	for _, tc := range cases {
		full := filepath.Join(root, filepath.FromSlash(tc.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(tc.body), 0o644); err != nil {
			t.Fatal(err)
		}
		info, ok := DetectManifest(full)
		if tc.wantType == "" {
			if ok {
				t.Errorf("%s: detected as %+v, want no detection", tc.path, info)
			}
			continue
		}
		if !ok || info.Type != tc.wantType {
			t.Errorf("%s: got %+v, want type %q", tc.path, info, tc.wantType)
		}
	}
}
