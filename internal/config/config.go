package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// TaskType represents the available task types
type TaskType string

const (
	TaskInfo   TaskType = "info"   // Default info/healthcheck
	TaskReport TaskType = "report" // Report generation
	TaskTriage TaskType = "triage" // Automated triage
)

// ToolFormat represents the supported artifact formats
type ToolFormat string

const (
	FormatSARIF     ToolFormat = "SARIF"
	FormatSBOM      ToolFormat = "SBOM"
	FormatCSAF_VEX  ToolFormat = "CSAF_VEX"
	FormatOpenVEX   ToolFormat = "OpenVEX"
	FormatCycloneDX ToolFormat = "CycloneDX_VEX"
	FormatVDR       ToolFormat = "VDR"
	FormatPlainJSON ToolFormat = "PLAIN_JSON"
	FormatPlainXML  ToolFormat = "PLAIN_XML"
	FormatBlob      ToolFormat = "BLOB"
)

// Tool represents a tool configuration for fetching artifacts
type Tool struct {
	Category           string     `yaml:"category" json:"category"`
	ArtifactName       string     `yaml:"artifact_name" json:"artifact_name"`
	Format             ToolFormat `yaml:"format" json:"format"`
	CustomerIdentifier string     `yaml:"customer_identifier" json:"customer_identifier"`
}

// RuntimePlatform represents the detected runtime environment
type RuntimePlatform string

const (
	PlatformGitHub      RuntimePlatform = "github"
	PlatformGitLab      RuntimePlatform = "gitlab"
	PlatformAzureDevOps RuntimePlatform = "azure"
	PlatformBitbucket   RuntimePlatform = "bitbucket"
	PlatformJenkins     RuntimePlatform = "jenkins"
	PlatformDocker      RuntimePlatform = "docker"
	PlatformKubernetes  RuntimePlatform = "kubernetes"
	PlatformPodman      RuntimePlatform = "podman"
	PlatformCLI         RuntimePlatform = "cli"
)

// CIContext contains normalized CI/CD context information
type CIContext struct {
	Platform         RuntimePlatform `json:"platform"`
	Repository       string          `json:"repository"`
	RepositoryOwner  string          `json:"repository_owner"`
	RunID            string          `json:"run_id"`
	RunNumber        string          `json:"run_number"`
	JobID            string          `json:"job_id"`
	SHA              string          `json:"sha"`
	RefName          string          `json:"ref_name"`
	RefType          string          `json:"ref_type"`
	HeadRef          string          `json:"head_ref"`
	BaseRef          string          `json:"base_ref"`
	EventName        string          `json:"event_name"`
	ServerURL        string          `json:"server_url"`
	APIURL           string          `json:"api_url"`
	Token            string          `json:"-"` // Don't serialize for security
	WorkspacePath    string          `json:"workspace_path"`
	RunnerOS         string          `json:"runner_os"`
	RunnerArch       string          `json:"runner_arch"`
	PlatformVersion  string          `json:"platform_version"`
	DetectedFeatures []string        `json:"detected_features"`
}

// VulnetixConfig represents the complete configuration state
type VulnetixConfig struct {
	// Core Vulnetix settings
	OrgID       string   `json:"org_id"`
	Task        TaskType `json:"task"`
	ProjectName string   `json:"project_name,omitempty"`
	ProductName string   `json:"product_name,omitempty"`
	TeamName    string   `json:"team_name,omitempty"`
	GroupName   string   `json:"group_name,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Tools       []Tool   `json:"tools,omitempty"`

	// CI/CD context (replaces GitHub-specific context)
	CI CIContext `json:"ci"`

	// Runtime info
	Version string `json:"version"`
}

// DetectPlatform detects the current runtime platform based on environment variables
func DetectPlatform() RuntimePlatform {
	// Check for GitHub Actions
	if getEnv("GITHUB_ACTIONS") == "true" || getEnv("GITHUB_RUN_ID") != "" {
		return PlatformGitHub
	}

	// Check for GitLab CI
	if getEnv("GITLAB_CI") == "true" || getEnv("CI_JOB_ID") != "" {
		return PlatformGitLab
	}

	// Check for Azure DevOps
	if getEnv("TF_BUILD") == "True" || getEnv("AZURE_HTTP_USER_AGENT") != "" || getEnv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI") != "" {
		return PlatformAzureDevOps
	}

	// Check for Bitbucket Pipelines
	if getEnv("BITBUCKET_BUILD_NUMBER") != "" || getEnv("BITBUCKET_COMMIT") != "" {
		return PlatformBitbucket
	}

	// Check for Jenkins
	if getEnv("JENKINS_URL") != "" || getEnv("BUILD_NUMBER") != "" {
		return PlatformJenkins
	}

	// Check for container runtimes
	if getEnv("KUBERNETES_SERVICE_HOST") != "" || getEnv("KUBERNETES_PORT") != "" {
		return PlatformKubernetes
	}

	if getEnv("container") == "podman" || getEnv("PODMAN_SYSTEMD_UNIT") != "" {
		return PlatformPodman
	}

	// Check for Docker (this should be last as it's most generic)
	if fileExists("/.dockerenv") || getEnv("DOCKER_CONTAINER") != "" {
		return PlatformDocker
	}

	// Default to CLI
	return PlatformCLI
}

// LoadCIContext loads CI/CD context based on detected platform
func LoadCIContext(version string) CIContext {
	platform := DetectPlatform()

	switch platform {
	case PlatformGitHub:
		return loadGitHubCIContext(version)
	case PlatformGitLab:
		return loadGitLabCIContext(version)
	case PlatformAzureDevOps:
		return loadAzureDevOpsCIContext(version)
	case PlatformBitbucket:
		return loadBitbucketCIContext(version)
	case PlatformJenkins:
		return loadJenkinsCIContext(version)
	case PlatformKubernetes:
		return loadKubernetesCIContext(version)
	case PlatformDocker:
		return loadDockerCIContext(version)
	case PlatformPodman:
		return loadPodmanCIContext(version)
	default:
		return loadCLICIContext(version)
	}
}

// loadGitHubCIContext loads GitHub Actions context
func loadGitHubCIContext(version string) CIContext {
	return CIContext{
		Platform:         PlatformGitHub,
		Repository:       getEnv("GITHUB_REPOSITORY"),
		RepositoryOwner:  getEnv("GITHUB_REPOSITORY_OWNER"),
		RunID:            getEnv("GITHUB_RUN_ID"),
		RunNumber:        getEnv("GITHUB_RUN_NUMBER"),
		JobID:            getEnv("GITHUB_JOB"),
		SHA:              getEnv("GITHUB_SHA"),
		RefName:          getEnv("GITHUB_REF_NAME"),
		RefType:          getEnv("GITHUB_REF_TYPE"),
		HeadRef:          getEnv("GITHUB_HEAD_REF"),
		BaseRef:          getEnv("GITHUB_BASE_REF"),
		EventName:        getEnv("GITHUB_EVENT_NAME"),
		ServerURL:        getEnv("GITHUB_SERVER_URL"),
		APIURL:           getEnv("GITHUB_API_URL"),
		Token:            getEnv("GITHUB_TOKEN"),
		WorkspacePath:    getEnv("GITHUB_WORKSPACE"),
		RunnerOS:         getEnv("RUNNER_OS"),
		RunnerArch:       getEnv("RUNNER_ARCH"),
		PlatformVersion:  getEnv("GITHUB_ACTION_REF"),
		DetectedFeatures: []string{"actions", "workflows", "artifacts"},
	}
}

// loadGitLabCIContext loads GitLab CI context
func loadGitLabCIContext(version string) CIContext {
	return CIContext{
		Platform:         PlatformGitLab,
		Repository:       getEnv("CI_PROJECT_PATH"),
		RepositoryOwner:  getEnv("CI_PROJECT_NAMESPACE"),
		RunID:            getEnv("CI_PIPELINE_ID"),
		RunNumber:        getEnv("CI_PIPELINE_IID"),
		JobID:            getEnv("CI_JOB_ID"),
		SHA:              getEnv("CI_COMMIT_SHA"),
		RefName:          getEnv("CI_COMMIT_REF_NAME"),
		RefType:          getRefType(getEnv("CI_COMMIT_REF_NAME"), getEnv("CI_COMMIT_TAG")),
		HeadRef:          getEnv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"),
		BaseRef:          getEnv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
		EventName:        getEnv("CI_PIPELINE_SOURCE"),
		ServerURL:        getEnv("CI_SERVER_URL"),
		APIURL:           getEnv("CI_API_V4_URL"),
		Token:            getEnv("CI_JOB_TOKEN"),
		WorkspacePath:    getEnv("CI_PROJECT_DIR"),
		RunnerOS:         getEnv("CI_RUNNER_TAGS"),
		RunnerArch:       getEnv("CI_RUNNER_EXECUTABLE_ARCH"),
		PlatformVersion:  getEnv("CI_SERVER_VERSION"),
		DetectedFeatures: []string{"pipelines", "jobs", "artifacts", "merge_requests"},
	}
}

// loadAzureDevOpsCIContext loads Azure DevOps context
func loadAzureDevOpsCIContext(version string) CIContext {
	return CIContext{
		Platform:         PlatformAzureDevOps,
		Repository:       getEnv("BUILD_REPOSITORY_NAME"),
		RepositoryOwner:  getEnv("SYSTEM_TEAMPROJECT"),
		RunID:            getEnv("BUILD_BUILDID"),
		RunNumber:        getEnv("BUILD_BUILDNUMBER"),
		JobID:            getEnv("SYSTEM_JOBID"),
		SHA:              getEnv("BUILD_SOURCEVERSION"),
		RefName:          getEnv("BUILD_SOURCEBRANCHNAME"),
		RefType:          getRefType(getEnv("BUILD_SOURCEBRANCHNAME"), ""),
		HeadRef:          getEnv("SYSTEM_PULLREQUEST_SOURCEBRANCH"),
		BaseRef:          getEnv("SYSTEM_PULLREQUEST_TARGETBRANCH"),
		EventName:        getEnv("BUILD_REASON"),
		ServerURL:        getEnv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"),
		APIURL:           getEnv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"),
		Token:            getEnv("SYSTEM_ACCESSTOKEN"),
		WorkspacePath:    getEnv("BUILD_SOURCESDIRECTORY"),
		RunnerOS:         getEnv("AGENT_OS"),
		RunnerArch:       getEnv("AGENT_OSARCHITECTURE"),
		PlatformVersion:  getEnv("AZURE_HTTP_USER_AGENT"),
		DetectedFeatures: []string{"builds", "releases", "artifacts", "pull_requests"},
	}
}

// loadBitbucketCIContext loads Bitbucket Pipelines context
func loadBitbucketCIContext(version string) CIContext {
	return CIContext{
		Platform:         PlatformBitbucket,
		Repository:       getEnv("BITBUCKET_REPO_FULL_NAME"),
		RepositoryOwner:  getEnv("BITBUCKET_REPO_OWNER"),
		RunID:            getEnv("BITBUCKET_BUILD_NUMBER"),
		RunNumber:        getEnv("BITBUCKET_BUILD_NUMBER"),
		JobID:            getEnv("BITBUCKET_STEP_UUID"),
		SHA:              getEnv("BITBUCKET_COMMIT"),
		RefName:          getEnv("BITBUCKET_BRANCH"),
		RefType:          getRefType(getEnv("BITBUCKET_BRANCH"), getEnv("BITBUCKET_TAG")),
		HeadRef:          getEnv("BITBUCKET_PR_ID"),
		BaseRef:          getEnv("BITBUCKET_PR_DESTINATION_BRANCH"),
		EventName:        determineBitbucketEvent(),
		ServerURL:        "https://bitbucket.org",
		APIURL:           "https://api.bitbucket.org/2.0",
		Token:            getEnv("BITBUCKET_ACCESS_TOKEN"),
		WorkspacePath:    getEnv("BITBUCKET_CLONE_DIR"),
		RunnerOS:         getEnv("BITBUCKET_STEP_RUNNER_TYPE"),
		RunnerArch:       "",
		PlatformVersion:  getEnv("BITBUCKET_PIPELINE_UUID"),
		DetectedFeatures: []string{"pipelines", "steps", "artifacts", "pull_requests"},
	}
}

// loadJenkinsCIContext loads Jenkins context
func loadJenkinsCIContext(version string) CIContext {
	return CIContext{
		Platform:         PlatformJenkins,
		Repository:       getEnv("GIT_URL"),
		RepositoryOwner:  extractOwnerFromGitURL(getEnv("GIT_URL")),
		RunID:            getEnv("BUILD_ID"),
		RunNumber:        getEnv("BUILD_NUMBER"),
		JobID:            getEnv("JOB_NAME"),
		SHA:              getEnv("GIT_COMMIT"),
		RefName:          getEnv("GIT_BRANCH"),
		RefType:          getRefType(getEnv("GIT_BRANCH"), ""),
		HeadRef:          getEnv("CHANGE_BRANCH"),
		BaseRef:          getEnv("CHANGE_TARGET"),
		EventName:        determineJenkinsEvent(),
		ServerURL:        getEnv("JENKINS_URL"),
		APIURL:           getEnv("JENKINS_URL"),
		Token:            getEnv("JENKINS_API_TOKEN"),
		WorkspacePath:    getEnv("WORKSPACE"),
		RunnerOS:         getEnv("NODE_LABELS"),
		RunnerArch:       "",
		PlatformVersion:  getEnv("JENKINS_VERSION"),
		DetectedFeatures: []string{"builds", "jobs", "artifacts", "multibranch"},
	}
}

// loadKubernetesCIContext loads Kubernetes context
func loadKubernetesCIContext(version string) CIContext {
	return CIContext{
		Platform:         PlatformKubernetes,
		Repository:       getEnv("REPO_NAME"),
		RepositoryOwner:  getEnv("REPO_OWNER"),
		RunID:            getEnv("POD_NAME"),
		RunNumber:        getEnv("JOB_COMPLETION_INDEX"),
		JobID:            getEnv("JOB_NAME"),
		SHA:              getEnv("GIT_COMMIT"),
		RefName:          getEnv("GIT_BRANCH"),
		RefType:          "branch",
		ServerURL:        "https://" + getEnv("KUBERNETES_SERVICE_HOST"),
		WorkspacePath:    "/workspace",
		RunnerOS:         "linux",
		PlatformVersion:  getEnv("KUBERNETES_SERVICE_PORT"),
		DetectedFeatures: []string{"pods", "jobs", "services", "configmaps"},
	}
}

// loadDockerCIContext loads Docker context
func loadDockerCIContext(version string) CIContext {
	return CIContext{
		Platform:         PlatformDocker,
		Repository:       getEnv("REPO_NAME"),
		RunID:            getEnv("HOSTNAME"),
		WorkspacePath:    "/workspace",
		RunnerOS:         getEnv("TARGETPLATFORM"),
		PlatformVersion:  getEnv("DOCKER_VERSION"),
		DetectedFeatures: []string{"containers", "volumes", "networks"},
	}
}

// loadPodmanCIContext loads Podman context
func loadPodmanCIContext(version string) CIContext {
	return CIContext{
		Platform:         PlatformPodman,
		Repository:       getEnv("REPO_NAME"),
		RunID:            getEnv("HOSTNAME"),
		WorkspacePath:    "/workspace",
		RunnerOS:         "linux",
		PlatformVersion:  getEnv("PODMAN_VERSION"),
		DetectedFeatures: []string{"containers", "pods", "volumes"},
	}
}

// loadCLICIContext loads CLI context with timestamp-based identification
func loadCLICIContext(version string) CIContext {
	timestamp := time.Now().Unix()
	runID := fmt.Sprintf("cli_%d_%s", timestamp, version)

	workDir, _ := os.Getwd()

	return CIContext{
		Platform:         PlatformCLI,
		Repository:       filepath.Base(workDir),
		RunID:            runID,
		RunNumber:        strconv.FormatInt(timestamp, 10),
		JobID:            "cli-job",
		WorkspacePath:    workDir,
		RunnerOS:         getOSName(),
		RunnerArch:       getArchName(),
		PlatformVersion:  version,
		DetectedFeatures: []string{"local", "cli", "manual"},
	}
}

// getEnv gets an environment variable with fallback to empty string
func getEnv(key string) string {
	return os.Getenv(key)
}

// ParseTags parses a comma-separated string of tags into a slice
func ParseTags(tagsStr string) []string {
	if tagsStr == "" {
		return nil
	}

	// Remove square brackets if present (YAML list format)
	tagsStr = strings.Trim(tagsStr, "[]")

	// Split by comma and clean up each tag
	parts := strings.Split(tagsStr, ",")
	var tags []string

	for _, part := range parts {
		// Clean up the tag: remove spaces, quotes, etc.
		tag := strings.TrimSpace(part)
		tag = strings.Trim(tag, "\"'")

		if tag != "" {
			tags = append(tags, tag)
		}
	}

	if len(tags) == 0 {
		return nil
	}

	return tags
}

// Helper functions
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func getRefType(refName, tag string) string {
	if tag != "" {
		return "tag"
	}
	if strings.Contains(refName, "refs/heads/") || refName != "" {
		return "branch"
	}
	return "unknown"
}

func extractOwnerFromGitURL(gitURL string) string {
	if gitURL == "" {
		return ""
	}
	// Simple extraction for common Git URL formats
	parts := strings.Split(gitURL, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

func determineBitbucketEvent() string {
	if getEnv("BITBUCKET_PR_ID") != "" {
		return "pull_request"
	}
	return "push"
}

func determineJenkinsEvent() string {
	if getEnv("CHANGE_ID") != "" {
		return "pull_request"
	}
	return "push"
}

func getOSName() string {
	if os := getEnv("RUNNER_OS"); os != "" {
		return strings.ToLower(os)
	}
	return "unknown"
}

func getArchName() string {
	if arch := getEnv("RUNNER_ARCH"); arch != "" {
		return arch
	}
	return "unknown"
}

// GenerateArtifactNamingConvention generates artifact naming based on parameters
// If toolCategory and baseArtifactName are provided, generates specific naming
// If no parameters, generates wildcard pattern for searching
func (c *VulnetixConfig) GenerateArtifactNamingConvention(params ...string) string {
	var baseRepo, runID string

	// Use CI context for more flexible naming
	if c.CI.Platform != "" && c.CI.Repository != "" && c.CI.RunID != "" {
		baseRepo = strings.ReplaceAll(c.CI.Repository, "/", "-")
		runID = c.CI.RunID
	} else {
		// Generic fallback
		if len(params) >= 2 {
			return fmt.Sprintf("vulnetix-%s-%s", params[0], params[1])
		}
		return "vulnetix-*"
	}

	if len(params) >= 2 {
		// Specific tool and artifact naming
		toolCategory := params[0]
		baseArtifactName := params[1]
		return fmt.Sprintf("vulnetix-%s-%s-%s-%s", baseRepo, runID, toolCategory, baseArtifactName)
	}

	// Wildcard pattern for searching
	return fmt.Sprintf("vulnetix-%s-%s-*", baseRepo, runID)
}

// PrintConfiguration prints the current configuration for debugging
func (c *VulnetixConfig) PrintConfiguration() {
	fmt.Printf("📋 Configuration Summary:\n")
	fmt.Printf("   Platform: %s\n", c.CI.Platform)
	fmt.Printf("   Repository: %s\n", c.CI.Repository)
	fmt.Printf("   Run ID: %s\n", c.CI.RunID)
	fmt.Printf("   Task: %s\n", c.Task)

	if c.ProjectName != "" {
		fmt.Printf("   Project: %s\n", c.ProjectName)
	}

	if c.TeamName != "" {
		fmt.Printf("   Team: %s\n", c.TeamName)
	}

	if len(c.Tags) > 0 {
		fmt.Printf("   Tags: %v\n", c.Tags)
	}

	if len(c.Tools) > 0 {
		fmt.Printf("   Tools: %d configured\n", len(c.Tools))
		for _, tool := range c.Tools {
			fmt.Printf("     - %s (%s): %s\n", tool.Category, tool.Format, tool.ArtifactName)
		}
	}

	fmt.Printf("   Features: %v\n", c.CI.DetectedFeatures)
	fmt.Println()
}

// ValidateTask validates that the specified task is supported
func ValidateTask(task string) (TaskType, error) {
	switch TaskType(task) {
	case TaskInfo, TaskReport, TaskTriage:
		return TaskType(task), nil
	case "":
		return TaskInfo, nil // Default to info
	default:
		return "", fmt.Errorf("unsupported task: %s. Supported tasks: info, report, triage", task)
	}
}

// GetWorkflowRunContext returns workflow run context information
func (c *VulnetixConfig) GetWorkflowRunContext() map[string]string {
	return map[string]string{
		"workflow_run_id":      c.CI.RunID,
		"workflow_run_number":  c.CI.RunNumber,
		"workflow_run_attempt": "1", // Default value
		"repository":           c.CI.Repository,
		"workflow_ref":         c.CI.RefName,
		"workflow_sha":         c.CI.SHA,
	}
}
