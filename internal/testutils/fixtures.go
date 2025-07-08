package testutils

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
