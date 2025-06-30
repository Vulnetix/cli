package testutils

// GitHubContextFixture provides a common set of GitHub context environment variables for testing.
func GitHubContextFixture() map[string]string {
	return map[string]string{
		"GITHUB_ACTIONS":        "true",
		"GITHUB_EVENT_NAME":     "push",
		"GITHUB_REF":            "refs/heads/main",
		"GITHUB_REPOSITORY":     "octocat/Spoon-Knife",
		"GITHUB_REPOSITORY_OWNER": "octocat",
		"GITHUB_RUN_ID":         "123456789",
		"GITHUB_RUN_NUMBER":     "1",
		"GITHUB_SHA":            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
		"GITHUB_WORKFLOW":       "build",
		"GITHUB_ACTOR":          "octocat",
		"GITHUB_JOB":            "build",
		"RUNNER_OS":             "Linux",
		"RUNNER_ARCH":           "X64",
		"RUNNER_TEMP":           "/tmp",
		"RUNNER_TOOL_CACHE":     "/opt/hostedtoolcache",
	}
}

// MinimalGitHubContextFixture provides a minimal set of GitHub context environment variables.
func MinimalGitHubContextFixture() map[string]string {
	return map[string]string{
		"GITHUB_ACTIONS":    "true",
		"GITHUB_REPOSITORY": "octocat/Spoon-Knife",
		"GITHUB_REF":        "refs/heads/main",
		"GITHUB_SHA":        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
	}
}

// ReleaseTaskConfigFixture provides a common configuration for a release task.
func ReleaseTaskConfigFixture() string {
	return `
version: 1
task: release
release:
  target_branch: main
  github_context:
    workflow_run_id: 123456789
    repository: octocat/Spoon-Knife
    ref: refs/heads/main
    sha: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
`
}

// ScanTaskConfigFixture provides a common configuration for a scan task.
func ScanTaskConfigFixture() string {
	return `
version: 1
task: scan
scan:
  target: .
  output: results.json
`
}
