package config

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTags(t *testing.T) {
	tests := []struct {
		name     string
		tagsStr  string
		expected []string
	}{
		{name: "Empty string", tagsStr: "", expected: nil},
		{name: "Single tag", tagsStr: "tag1", expected: []string{"tag1"}},
		{name: "Multiple tags comma separated", tagsStr: "tag1, tag2,tag3", expected: []string{"tag1", "tag2", "tag3"}},
		{name: "Tags with spaces", tagsStr: "  tag1  ,  tag2  ", expected: []string{"tag1", "tag2"}},
		{name: "Tags with YAML list markers", tagsStr: "[tag1, tag2]", expected: []string{"tag1", "tag2"}},
		{name: "Tags with quotes", tagsStr: "'tag1', \"tag2\"", expected: []string{"tag1", "tag2"}},
		{name: "Mixed case tags", tagsStr: "TagA, tagB", expected: []string{"TagA", "tagB"}},
		{name: "Tags with special characters", tagsStr: "tag-1, tag_2", expected: []string{"tag-1", "tag_2"}},
		{name: "Only spaces", tagsStr: "   ", expected: nil},
		{name: "Empty tags in between", tagsStr: "tag1,,tag2", expected: []string{"tag1", "tag2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := ParseTags(tt.tagsStr)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestGenerateArtifactNamingConvention(t *testing.T) {
	tests := []struct {
		name             string
		config           *VulnetixConfig
		toolCategory     string
		baseArtifactName string
		expected         string
	}{
		{
			name: "Standard case",
			config: &VulnetixConfig{
				CI: CIContext{
					Platform:   PlatformGitHub,
					Repository: "octocat/Spoon-Knife",
					RunID:      "123456789",
				},
			},
			toolCategory:     "sast",
			baseArtifactName: "results.sarif",
			expected:         "vulnetix-octocat-Spoon-Knife-123456789-sast-results.sarif",
		},
		{
			name: "Repository with hyphens",
			config: &VulnetixConfig{
				CI: CIContext{
					Platform:   PlatformGitHub,
					Repository: "my-org/my-repo",
					RunID:      "98765",
				},
			},
			toolCategory:     "sca",
			baseArtifactName: "sbom.json",
			expected:         "vulnetix-my-org-my-repo-98765-sca-sbom.json",
		},
		{
			name: "Empty base artifact name",
			config: &VulnetixConfig{
				CI: CIContext{
					Platform:   PlatformGitHub,
					Repository: "test/repo",
					RunID:      "111",
				},
			},
			toolCategory:     "secret",
			baseArtifactName: "",
			expected:         "vulnetix-test-repo-111-secret-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.config.GenerateArtifactNamingConvention(tt.toolCategory, tt.baseArtifactName)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestGetWorkflowRunContext(t *testing.T) {
	config := &VulnetixConfig{
		CI: CIContext{
			RunID:      "run-123",
			RunNumber:  "1",
			Repository: "test/repo",
			RefName:    "refs/heads/main",
			SHA:        "abcdef",
		},
	}

	expected := map[string]string{
		"workflow_run_id":      "run-123",
		"workflow_run_number":  "1",
		"workflow_run_attempt": "1",
		"repository":           "test/repo",
		"workflow_ref":         "refs/heads/main",
		"workflow_sha":         "abcdef",
	}

	actual := config.GetWorkflowRunContext()
	assert.Equal(t, expected, actual)
}

// ciEnvKeys is every variable DetectPlatform and the load*CIContext functions
// read. The suite itself runs on GitHub Actions, where GITHUB_ACTIONS and
// GITHUB_RUN_ID are set and win detection, so each case starts from a blank
// slate rather than inheriting the runner's environment.
var ciEnvKeys = []string{
	"AGENT_OS", "AGENT_OSARCHITECTURE", "AZURE_HTTP_USER_AGENT", "BITBUCKET_ACCESS_TOKEN",
	"BITBUCKET_BRANCH", "BITBUCKET_BUILD_NUMBER", "BITBUCKET_CLONE_DIR", "BITBUCKET_COMMIT",
	"BITBUCKET_PIPELINE_UUID", "BITBUCKET_PR_DESTINATION_BRANCH", "BITBUCKET_PR_ID",
	"BITBUCKET_REPO_FULL_NAME", "BITBUCKET_REPO_OWNER", "BITBUCKET_STEP_RUNNER_TYPE",
	"BITBUCKET_STEP_UUID", "BITBUCKET_TAG", "BUILD_BUILDID", "BUILD_BUILDNUMBER",
	"BUILD_ID", "BUILD_NUMBER", "BUILD_REASON", "BUILD_REPOSITORY_NAME",
	"BUILD_SOURCEBRANCHNAME", "BUILD_SOURCESDIRECTORY", "BUILD_SOURCEVERSION",
	"CHANGE_BRANCH", "CHANGE_ID", "CHANGE_TARGET", "CI_API_V4_URL", "CI_COMMIT_REF_NAME",
	"CI_COMMIT_SHA", "CI_COMMIT_TAG", "CI_JOB_ID", "CI_JOB_TOKEN",
	"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
	"CI_PIPELINE_ID", "CI_PIPELINE_IID", "CI_PIPELINE_SOURCE", "CI_PROJECT_DIR",
	"CI_PROJECT_NAMESPACE", "CI_PROJECT_PATH", "CI_RUNNER_EXECUTABLE_ARCH",
	"CI_RUNNER_TAGS", "CI_SERVER_URL", "CI_SERVER_VERSION", "container", "DOCKER_CONTAINER",
	"DOCKER_VERSION", "GIT_BRANCH", "GIT_COMMIT", "GIT_URL", "GITHUB_ACTION_REF",
	"GITHUB_ACTIONS", "GITHUB_API_URL", "GITHUB_BASE_REF", "GITHUB_EVENT_NAME",
	"GITHUB_HEAD_REF", "GITHUB_JOB", "GITHUB_REF_NAME", "GITHUB_REF_TYPE",
	"GITHUB_REPOSITORY", "GITHUB_REPOSITORY_OWNER", "GITHUB_RUN_ID", "GITHUB_RUN_NUMBER",
	"GITHUB_SERVER_URL", "GITHUB_SHA", "GITHUB_TOKEN", "GITHUB_WORKSPACE", "GITLAB_CI",
	"HOSTNAME", "JENKINS_API_TOKEN", "JENKINS_URL", "JENKINS_VERSION",
	"JOB_COMPLETION_INDEX", "JOB_NAME", "KUBERNETES_PORT", "KUBERNETES_SERVICE_HOST",
	"KUBERNETES_SERVICE_PORT", "NODE_LABELS", "POD_NAME", "PODMAN_SYSTEMD_UNIT",
	"PODMAN_VERSION", "REPO_NAME", "REPO_OWNER", "RUNNER_ARCH", "RUNNER_OS",
	"SYSTEM_ACCESSTOKEN", "SYSTEM_JOBID", "SYSTEM_PULLREQUEST_SOURCEBRANCH",
	"SYSTEM_PULLREQUEST_TARGETBRANCH", "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI",
	"SYSTEM_TEAMPROJECT", "TARGETPLATFORM", "TF_BUILD", "WORKSPACE",
}

// clearCIEnv blanks every CI variable for the duration of the test. getEnv
// treats an empty value the same as an unset one.
func clearCIEnv(t *testing.T) {
	t.Helper()
	for _, k := range ciEnvKeys {
		t.Setenv(k, "")
	}
}

func TestDetectPlatform(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		expected RuntimePlatform
	}{
		{
			name:     "GitHub Actions",
			env:      map[string]string{"GITHUB_ACTIONS": "true"},
			expected: PlatformGitHub,
		},
		{
			name:     "GitHub run id only",
			env:      map[string]string{"GITHUB_RUN_ID": "12345"},
			expected: PlatformGitHub,
		},
		{
			name:     "GitLab CI",
			env:      map[string]string{"GITLAB_CI": "true"},
			expected: PlatformGitLab,
		},
		{
			name:     "Azure DevOps",
			env:      map[string]string{"TF_BUILD": "True"},
			expected: PlatformAzureDevOps,
		},
		{
			name:     "Bitbucket",
			env:      map[string]string{"BITBUCKET_COMMIT": "abc123"},
			expected: PlatformBitbucket,
		},
		{
			name: "Jenkins",
			env: map[string]string{
				"JENKINS_URL": "http://jenkins.example/",
			},
			expected: PlatformJenkins,
		},
		{
			name:     "Kubernetes",
			env:      map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"},
			expected: PlatformKubernetes,
		},
		{
			name:     "Podman",
			env:      map[string]string{"container": "podman"},
			expected: PlatformPodman,
		},
		{
			name:     "Docker via env",
			env:      map[string]string{"DOCKER_CONTAINER": "yes"},
			expected: PlatformDocker,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearCIEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			assert.Equal(t, tt.expected, DetectPlatform())
		})
	}

	// With no CI markers the answer is CLI, unless the host is a Docker
	// container, where the /.dockerenv file check wins. Either way it is
	// deterministic for the host the test runs on.
	t.Run("no CI markers", func(t *testing.T) {
		clearCIEnv(t)
		want := PlatformCLI
		if fileExists("/.dockerenv") {
			want = PlatformDocker
		}
		assert.Equal(t, want, DetectPlatform())
	})
}

func TestLoadCIContext(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		expected CIContext
	}{
		{
			name: "GitHub context",
			env: map[string]string{
				"GITHUB_REPOSITORY":       "octocat/Spoon-Knife",
				"GITHUB_REPOSITORY_OWNER": "octocat",
				"GITHUB_RUN_ID":           "run-1",
				"GITHUB_RUN_NUMBER":       "42",
				"GITHUB_JOB":              "test",
				"GITHUB_SHA":              "deadbeef",
				"GITHUB_REF_NAME":         "main",
				"GITHUB_REF_TYPE":         "branch",
				"GITHUB_HEAD_REF":         "feature",
				"GITHUB_BASE_REF":         "main",
				"GITHUB_EVENT_NAME":       "push",
				"GITHUB_SERVER_URL":       "https://github.com",
				"GITHUB_API_URL":          "https://api.github.com",
				"GITHUB_TOKEN":            "secret",
				"GITHUB_WORKSPACE":        "/workspace",
				"RUNNER_OS":               "Linux",
				"RUNNER_ARCH":             "X64",
				"GITHUB_ACTION_REF":       "v1.2.3",
			},
			expected: CIContext{
				Platform:         PlatformGitHub,
				Repository:       "octocat/Spoon-Knife",
				RepositoryOwner:  "octocat",
				RunID:            "run-1",
				RunNumber:        "42",
				JobID:            "test",
				SHA:              "deadbeef",
				RefName:          "main",
				RefType:          "branch",
				HeadRef:          "feature",
				BaseRef:          "main",
				EventName:        "push",
				ServerURL:        "https://github.com",
				APIURL:           "https://api.github.com",
				Token:            "secret",
				WorkspacePath:    "/workspace",
				RunnerOS:         "Linux",
				RunnerArch:       "X64",
				PlatformVersion:  "v1.2.3",
				DetectedFeatures: []string{"actions", "workflows", "artifacts"},
			},
		},
		{
			name: "GitLab context",
			env: map[string]string{
				"GITLAB_CI":                           "true",
				"CI_PROJECT_PATH":                     "group/project",
				"CI_PROJECT_NAMESPACE":                "group",
				"CI_PIPELINE_ID":                      "pipe-1",
				"CI_PIPELINE_IID":                     "7",
				"CI_JOB_ID":                           "job-9",
				"CI_COMMIT_SHA":                       "cafebabe",
				"CI_COMMIT_REF_NAME":                  "main",
				"CI_COMMIT_TAG":                       "",
				"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feature",
				"CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
				"CI_PIPELINE_SOURCE":                  "push",
				"CI_SERVER_URL":                       "https://gitlab.com",
				"CI_API_V4_URL":                       "https://gitlab.com/api/v4",
				"CI_JOB_TOKEN":                        "token",
				"CI_PROJECT_DIR":                      "/builds/group/project",
				"CI_RUNNER_TAGS":                      "docker",
				"CI_RUNNER_EXECUTABLE_ARCH":           "linux/amd64",
				"CI_SERVER_VERSION":                   "16.0",
			},
			expected: CIContext{
				Platform:         PlatformGitLab,
				Repository:       "group/project",
				RepositoryOwner:  "group",
				RunID:            "pipe-1",
				RunNumber:        "7",
				JobID:            "job-9",
				SHA:              "cafebabe",
				RefName:          "main",
				RefType:          "branch",
				HeadRef:          "feature",
				BaseRef:          "main",
				EventName:        "push",
				ServerURL:        "https://gitlab.com",
				APIURL:           "https://gitlab.com/api/v4",
				Token:            "token",
				WorkspacePath:    "/builds/group/project",
				RunnerOS:         "docker",
				RunnerArch:       "linux/amd64",
				PlatformVersion:  "16.0",
				DetectedFeatures: []string{"pipelines", "jobs", "artifacts", "merge_requests"},
			},
		},
		{
			name: "Azure DevOps context",
			env: map[string]string{
				"TF_BUILD":                           "True",
				"BUILD_REPOSITORY_NAME":              "repo",
				"SYSTEM_TEAMPROJECT":                 "proj",
				"BUILD_BUILDID":                      "build-1",
				"BUILD_BUILDNUMBER":                  "20241026.1",
				"SYSTEM_JOBID":                       "job-1",
				"BUILD_SOURCEVERSION":                "baddad",
				"BUILD_SOURCEBRANCHNAME":             "main",
				"SYSTEM_PULLREQUEST_SOURCEBRANCH":    "feature",
				"SYSTEM_PULLREQUEST_TARGETBRANCH":    "main",
				"BUILD_REASON":                       "IndividualCI",
				"SYSTEM_TEAMFOUNDATIONCOLLECTIONURI": "https://dev.azure.com/org/",
				"SYSTEM_ACCESSTOKEN":                 "token",
				"BUILD_SOURCESDIRECTORY":             "/src",
				"AGENT_OS":                           "Linux",
				"AGENT_OSARCHITECTURE":               "X64",
				"AZURE_HTTP_USER_AGENT":              "azure-devops/1.0",
			},
			expected: CIContext{
				Platform:         PlatformAzureDevOps,
				Repository:       "repo",
				RepositoryOwner:  "proj",
				RunID:            "build-1",
				RunNumber:        "20241026.1",
				JobID:            "job-1",
				SHA:              "baddad",
				RefName:          "main",
				RefType:          "branch",
				HeadRef:          "feature",
				BaseRef:          "main",
				EventName:        "IndividualCI",
				ServerURL:        "https://dev.azure.com/org/",
				APIURL:           "https://dev.azure.com/org/",
				Token:            "token",
				WorkspacePath:    "/src",
				RunnerOS:         "Linux",
				RunnerArch:       "X64",
				PlatformVersion:  "azure-devops/1.0",
				DetectedFeatures: []string{"builds", "releases", "artifacts", "pull_requests"},
			},
		},
		{
			name: "Bitbucket context",
			env: map[string]string{
				"BITBUCKET_BUILD_NUMBER":          "99",
				"BITBUCKET_COMMIT":                "aabbccdd",
				"BITBUCKET_REPO_FULL_NAME":        "team/repo",
				"BITBUCKET_REPO_OWNER":            "team",
				"BITBUCKET_STEP_UUID":             "{uuid}",
				"BITBUCKET_BRANCH":                "main",
				"BITBUCKET_TAG":                   "",
				"BITBUCKET_PR_ID":                 "",
				"BITBUCKET_PR_DESTINATION_BRANCH": "main",
				"BITBUCKET_CLONE_DIR":             "/opt/atlassian",
				"BITBUCKET_STEP_RUNNER_TYPE":      "docker",
				"BITBUCKET_PIPELINE_UUID":         "{pipeline}",
			},
			expected: CIContext{
				Platform:         PlatformBitbucket,
				Repository:       "team/repo",
				RepositoryOwner:  "team",
				RunID:            "99",
				RunNumber:        "99",
				JobID:            "{uuid}",
				SHA:              "aabbccdd",
				RefName:          "main",
				RefType:          "branch",
				HeadRef:          "",
				BaseRef:          "main",
				EventName:        "push",
				ServerURL:        "https://bitbucket.org",
				APIURL:           "https://api.bitbucket.org/2.0",
				Token:            "",
				WorkspacePath:    "/opt/atlassian",
				RunnerOS:         "docker",
				RunnerArch:       "",
				PlatformVersion:  "{pipeline}",
				DetectedFeatures: []string{"pipelines", "steps", "artifacts", "pull_requests"},
			},
		},
		{
			name: "Jenkins context",
			env: map[string]string{
				"JENKINS_URL":     "https://jenkins.example/",
				"GIT_URL":         "https://github.com/org/repo.git",
				"BUILD_ID":        "build-5",
				"BUILD_NUMBER":    "5",
				"JOB_NAME":        "job",
				"GIT_COMMIT":      "abc123",
				"GIT_BRANCH":      "main",
				"CHANGE_BRANCH":   "feature",
				"CHANGE_TARGET":   "main",
				"CHANGE_ID":       "42",
				"WORKSPACE":       "/jenkins/workspace",
				"NODE_LABELS":     "linux docker",
				"JENKINS_VERSION": "2.414",
			},
			expected: CIContext{
				Platform:         PlatformJenkins,
				Repository:       "https://github.com/org/repo.git",
				RepositoryOwner:  "org",
				RunID:            "build-5",
				RunNumber:        "5",
				JobID:            "job",
				SHA:              "abc123",
				RefName:          "main",
				RefType:          "branch",
				HeadRef:          "feature",
				BaseRef:          "main",
				EventName:        "pull_request",
				ServerURL:        "https://jenkins.example/",
				APIURL:           "https://jenkins.example/",
				Token:            "",
				WorkspacePath:    "/jenkins/workspace",
				RunnerOS:         "linux docker",
				RunnerArch:       "",
				PlatformVersion:  "2.414",
				DetectedFeatures: []string{"builds", "jobs", "artifacts", "multibranch"},
			},
		},
		{
			name: "Kubernetes context",
			env: map[string]string{
				"KUBERNETES_SERVICE_HOST": "k8s",
				"REPO_NAME":               "repo",
				"REPO_OWNER":              "owner",
				"POD_NAME":                "pod-1",
				"JOB_COMPLETION_INDEX":    "0",
				"JOB_NAME":                "job",
				"GIT_COMMIT":              "commit",
				"GIT_BRANCH":              "main",
				"KUBERNETES_SERVICE_PORT": "443",
			},
			expected: CIContext{
				Platform:         PlatformKubernetes,
				Repository:       "repo",
				RepositoryOwner:  "owner",
				RunID:            "pod-1",
				RunNumber:        "0",
				JobID:            "job",
				SHA:              "commit",
				RefName:          "main",
				RefType:          "branch",
				HeadRef:          "",
				BaseRef:          "",
				EventName:        "",
				ServerURL:        "https://k8s",
				APIURL:           "",
				Token:            "",
				WorkspacePath:    "/workspace",
				RunnerOS:         "linux",
				RunnerArch:       "",
				PlatformVersion:  "443",
				DetectedFeatures: []string{"pods", "jobs", "services", "configmaps"},
			},
		},
		{
			name: "Docker context",
			env: map[string]string{
				"DOCKER_CONTAINER": "yes",
				"REPO_NAME":        "repo",
				"HOSTNAME":         "container-1",
				"DOCKER_VERSION":   "24.0",
				"TARGETPLATFORM":   "linux/amd64",
			},
			expected: CIContext{
				Platform:         PlatformDocker,
				Repository:       "repo",
				RunID:            "container-1",
				WorkspacePath:    "/workspace",
				RunnerOS:         "linux/amd64",
				PlatformVersion:  "24.0",
				DetectedFeatures: []string{"containers", "volumes", "networks"},
			},
		},
		{
			name: "Podman context",
			env: map[string]string{
				"container":      "podman",
				"REPO_NAME":      "repo",
				"HOSTNAME":       "pod-1",
				"PODMAN_VERSION": "4.7",
			},
			expected: CIContext{
				Platform:         PlatformPodman,
				Repository:       "repo",
				RunID:            "pod-1",
				WorkspacePath:    "/workspace",
				RunnerOS:         "linux",
				PlatformVersion:  "4.7",
				DetectedFeatures: []string{"containers", "pods", "volumes"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearCIEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			assert.Equal(t, tt.expected, LoadCIContext("v1.0.0"))
		})
	}
}

func TestLoadCLICIContext(t *testing.T) {
	ctx := loadCLICIContext("v1.0.0")

	assert.Equal(t, PlatformCLI, ctx.Platform)
	assert.Equal(t, "cli-job", ctx.JobID)
	assert.Equal(t, "v1.0.0", ctx.PlatformVersion)
	assert.True(t, strings.HasPrefix(ctx.RunID, "cli_"))
	assert.NotEmpty(t, ctx.RunNumber)
	assert.NotEmpty(t, ctx.WorkspacePath)
	assert.Equal(t, []string{"local", "cli", "manual"}, ctx.DetectedFeatures)
}

func TestOwnerFromGitURL(t *testing.T) {
	tests := []struct {
		name     string
		gitURL   string
		expected string
	}{
		{name: "empty", gitURL: "", expected: ""},
		{name: "https github", gitURL: "https://github.com/octocat/Spoon-Knife.git", expected: "octocat"},
		{name: "ssh github", gitURL: "git@github.com:octocat/Spoon-Knife.git", expected: "git@github.com:octocat"},
		{name: "single slash", gitURL: "owner/repo", expected: "owner"},
		{name: "trailing slash", gitURL: "https://github.com/org/repo/", expected: "repo"},
		{name: "only one segment", gitURL: "repo", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, OwnerFromGitURL(tt.gitURL))
		})
	}
}

func TestGenerateArtifactNamingConventionFallbacks(t *testing.T) {
	t.Run("wildcard when CI context is missing", func(t *testing.T) {
		cfg := &VulnetixConfig{}
		assert.Equal(t, "vulnetix-*", cfg.GenerateArtifactNamingConvention())
	})

	t.Run("explicit params when CI context is missing", func(t *testing.T) {
		cfg := &VulnetixConfig{}
		assert.Equal(t, "vulnetix-a-b", cfg.GenerateArtifactNamingConvention("a", "b"))
	})

	t.Run("wildcard with CI context", func(t *testing.T) {
		cfg := &VulnetixConfig{
			CI: CIContext{
				Platform:   PlatformGitHub,
				Repository: "org/my-repo",
				RunID:      "run-2",
			},
		}
		assert.Equal(t, "vulnetix-org-my-repo-run-2-*", cfg.GenerateArtifactNamingConvention())
	})
}

func TestPrintConfiguration(t *testing.T) {
	cfg := &VulnetixConfig{
		Task:        TaskInfo,
		ProjectName: "demo",
		TeamName:    "security",
		Tags:        []string{"a", "b"},
		CI: CIContext{
			Platform:         PlatformGitHub,
			Repository:       "org/repo",
			RunID:            "run-5",
			DetectedFeatures: []string{"actions"},
		},
		Tools: []Tool{
			{Category: "sast", Format: FormatSARIF, ArtifactName: "out.sarif"},
		},
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	cfg.PrintConfiguration()
	w.Close()
	os.Stdout = old

	out, _ := io.ReadAll(r)
	got := string(out)

	assert.Contains(t, got, "Configuration Summary")
	assert.Contains(t, got, "Platform: github")
	assert.Contains(t, got, "Repository: org/repo")
	assert.Contains(t, got, "Run ID: run-5")
	assert.Contains(t, got, "Task: info")
	assert.Contains(t, got, "Project: demo")
	assert.Contains(t, got, "Team: security")
	assert.Contains(t, got, "Tags: [a b]")
	assert.Contains(t, got, "Tools: 1 configured")
	assert.Contains(t, got, "sast (SARIF): out.sarif")
	assert.Contains(t, got, "Features: [actions]")
}

func TestGetRefType(t *testing.T) {
	tests := []struct {
		name     string
		refName  string
		tag      string
		expected string
	}{
		{name: "empty both", refName: "", tag: "", expected: "unknown"},
		{name: "tag wins", refName: "refs/heads/main", tag: "v1.0.0", expected: "tag"},
		{name: "refs/heads", refName: "refs/heads/main", tag: "", expected: "branch"},
		{name: "plain branch", refName: "main", tag: "", expected: "branch"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, getRefType(tt.refName, tt.tag))
		})
	}
}
