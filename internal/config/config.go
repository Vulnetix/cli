package config

import (
	"fmt"
	"os"
	"strings"
)

// TaskType represents the available task types
type TaskType string

const (
	TaskScan    TaskType = "scan"    // Default vulnerability scanning
	TaskRelease TaskType = "release" // Release readiness assessment
	TaskReport  TaskType = "report"  // Generate reports
	TaskTriage  TaskType = "triage"  // Automated triage
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

// GitHubContext contains all GitHub-specific environment variables
type GitHubContext struct {
	// Core GitHub vars
	Actor           string `json:"actor"`
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	RunID           string `json:"run_id"`
	RunNumber       string `json:"run_number"`
	RunAttempt      string `json:"run_attempt"`
	JobID           string `json:"job_id"`
	WorkflowRef     string `json:"workflow_ref"`
	WorkflowSHA     string `json:"workflow_sha"`
	Workspace       string `json:"workspace"`

	// Git context
	SHA     string `json:"sha"`
	RefName string `json:"ref_name"`
	RefType string `json:"ref_type"`
	HeadRef string `json:"head_ref"`
	BaseRef string `json:"base_ref"`

	// Event context
	EventName string `json:"event_name"`
	EventPath string `json:"event_path"`

	// Action context
	ActionPath       string `json:"action_path"`
	ActionRepository string `json:"action_repository"`

	// Server and API
	ServerURL  string `json:"server_url"`
	APIURL     string `json:"api_url"`
	GraphQLURL string `json:"graphql_url"`

	// Token (sensitive - handle carefully)
	Token string `json:"-"` // Don't serialize for security

	// Additional context
	RetentionDays   string `json:"retention_days"`
	RunnerOS        string `json:"runner_os"`
	RunnerArch      string `json:"runner_arch"`
	RunnerName      string `json:"runner_name"`
	RunnerTemp      string `json:"runner_temp"`
	RunnerToolCache string `json:"runner_tool_cache"`
}

// ReleaseConfig represents release readiness assessment configuration
type ReleaseConfig struct {
	Enabled          bool   `json:"enabled"`
	ProductionBranch string `json:"production_branch"`
	ReleaseBranch    string `json:"release_branch"`
	WorkflowTimeout  int    `json:"workflow_timeout_minutes"`

	// Assessment criteria
	RequiredFormats []ToolFormat `json:"required_formats"`
	MinToolCount    int          `json:"min_tool_count"`
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

	// Release readiness configuration
	Release ReleaseConfig `json:"release,omitempty"`

	// GitHub context
	GitHub GitHubContext `json:"github"`

	// Runtime info
	Version string `json:"version"`
}

// LoadGitHubContext reads all GitHub environment variables
func LoadGitHubContext() GitHubContext {
	return GitHubContext{
		Actor:            getEnv("GITHUB_ACTOR"),
		Repository:       getEnv("GITHUB_REPOSITORY"),
		RepositoryOwner:  getEnv("GITHUB_REPOSITORY_OWNER"),
		RunID:            getEnv("GITHUB_RUN_ID"),
		RunNumber:        getEnv("GITHUB_RUN_NUMBER"),
		RunAttempt:       getEnv("GITHUB_RUN_ATTEMPT"),
		JobID:            getEnv("GITHUB_JOB"),
		WorkflowRef:      getEnv("GITHUB_WORKFLOW_REF"),
		WorkflowSHA:      getEnv("GITHUB_WORKFLOW_SHA"),
		Workspace:        getEnv("GITHUB_WORKSPACE"),
		SHA:              getEnv("GITHUB_SHA"),
		RefName:          getEnv("GITHUB_REF_NAME"),
		RefType:          getEnv("GITHUB_REF_TYPE"),
		HeadRef:          getEnv("GITHUB_HEAD_REF"),
		BaseRef:          getEnv("GITHUB_BASE_REF"),
		EventName:        getEnv("GITHUB_EVENT_NAME"),
		EventPath:        getEnv("GITHUB_EVENT_PATH"),
		ActionPath:       getEnv("GITHUB_ACTION_PATH"),
		ActionRepository: getEnv("GITHUB_ACTION_REPOSITORY"),
		ServerURL:        getEnv("GITHUB_SERVER_URL"),
		APIURL:           getEnv("GITHUB_API_URL"),
		GraphQLURL:       getEnv("GITHUB_GRAPHQL_URL"),
		Token:            getEnv("GITHUB_TOKEN"),
		RetentionDays:    getEnv("GITHUB_RETENTION_DAYS"),
		RunnerOS:         getEnv("RUNNER_OS"),
		RunnerArch:       getEnv("RUNNER_ARCH"),
		RunnerName:       getEnv("RUNNER_NAME"),
		RunnerTemp:       getEnv("RUNNER_TEMP"),
		RunnerToolCache:  getEnv("RUNNER_TOOL_CACHE"),
	}
}

// getEnv gets an environment variable with fallback to empty string
func getEnv(key string) string {
	return os.Getenv(key)
}

// ParseTags parses a string of tags into a slice
func ParseTags(tagsStr string) []string {
	if tagsStr == "" {
		return nil
	}

	// Remove YAML list markers and split
	cleaned := strings.ReplaceAll(tagsStr, "[", "")
	cleaned = strings.ReplaceAll(cleaned, "]", "")
	cleaned = strings.ReplaceAll(cleaned, "\"", "")
	cleaned = strings.ReplaceAll(cleaned, "'", "")

	tags := strings.Split(cleaned, ",")
	var result []string
	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// GenerateArtifactNamingConvention creates a standardized artifact naming pattern
func (c *VulnetixConfig) GenerateArtifactNamingConvention(toolCategory, baseArtifactName string) string {
	// Pattern: vulnetix-{repo_name}-{run_id}-{tool_category}-{base_name}
	// This allows easy identification and linking of artifacts across jobs

	repoName := strings.Replace(c.GitHub.Repository, "/", "-", -1)
	return fmt.Sprintf("vulnetix-%s-%s-%s-%s",
		repoName,
		c.GitHub.RunID,
		strings.ToLower(toolCategory),
		baseArtifactName)
}

// GetWorkflowRunContext returns context that can help link sibling jobs
func (c *VulnetixConfig) GetWorkflowRunContext() map[string]string {
	return map[string]string{
		"workflow_run_id":      c.GitHub.RunID,
		"workflow_run_number":  c.GitHub.RunNumber,
		"workflow_run_attempt": c.GitHub.RunAttempt,
		"repository":           c.GitHub.Repository,
		"workflow_ref":         c.GitHub.WorkflowRef,
		"workflow_sha":         c.GitHub.WorkflowSHA,
	}
}

// ValidateReleaseReadiness validates that the release configuration meets requirements
func (c *VulnetixConfig) ValidateReleaseReadiness() error {
	if c.Task != TaskRelease {
		return nil
	}

	// Validate branch configuration
	if c.Release.ProductionBranch == "" {
		return fmt.Errorf("production branch is required for release readiness assessment")
	}

	if c.Release.ReleaseBranch == "" {
		return fmt.Errorf("release branch is required for release readiness assessment")
	}

	// Validate GitHub context for release assessment
	if c.GitHub.RunID == "" {
		return fmt.Errorf("GitHub run ID is required for artifact linking")
	}

	if c.GitHub.Repository == "" {
		return fmt.Errorf("GitHub repository is required for artifact scoping")
	}

	return nil
}

// GetReleaseArtifactPattern returns the artifact naming pattern for release assessment
func (c *VulnetixConfig) GetReleaseArtifactPattern() string {
	// Pattern for finding release-related artifacts
	// vulnetix-{repo_name}-{run_id}-*
	repoName := strings.Replace(c.GitHub.Repository, "/", "-", -1)
	return fmt.Sprintf("vulnetix-%s-%s-*", repoName, c.GitHub.RunID)
}

// GetSiblingJobsContext returns context for identifying related workflow jobs
func (c *VulnetixConfig) GetSiblingJobsContext() map[string]interface{} {
	return map[string]interface{}{
		"workflow_run_id":      c.GitHub.RunID,
		"workflow_run_number":  c.GitHub.RunNumber,
		"workflow_run_attempt": c.GitHub.RunAttempt,
		"repository":           c.GitHub.Repository,
		"workflow_ref":         c.GitHub.WorkflowRef,
		"workflow_sha":         c.GitHub.WorkflowSHA,
		"event_name":           c.GitHub.EventName,
		"head_ref":             c.GitHub.HeadRef,
		"base_ref":             c.GitHub.BaseRef,
		"artifact_pattern":     c.GetReleaseArtifactPattern(),
		"api_url":              c.GitHub.APIURL,
		"timeout_minutes":      c.Release.WorkflowTimeout,
	}
}

// PrintConfiguration prints the current configuration state
func (c *VulnetixConfig) PrintConfiguration() {
	fmt.Printf("🛡️  Vulnetix Configuration State\n")
	fmt.Printf("================================\n\n")

	fmt.Printf("Core Configuration:\n")
	fmt.Printf("  Organization ID: %s\n", c.OrgID)
	fmt.Printf("  Task: %s\n", c.Task)
	if c.ProjectName != "" {
		fmt.Printf("  Project Name: %s\n", c.ProjectName)
	}
	if c.ProductName != "" {
		fmt.Printf("  Product Name: %s\n", c.ProductName)
	}
	if c.TeamName != "" {
		fmt.Printf("  Team Name: %s\n", c.TeamName)
	}
	if c.GroupName != "" {
		fmt.Printf("  Group Name: %s\n", c.GroupName)
	}
	if len(c.Tags) > 0 {
		fmt.Printf("  Tags: %v\n", c.Tags)
	}

	if len(c.Tools) > 0 {
		fmt.Printf("\nTool Configurations:\n")
		for i, tool := range c.Tools {
			fmt.Printf("  Tool %d:\n", i+1)
			fmt.Printf("    Category: %s\n", tool.Category)
			fmt.Printf("    Artifact Name: %s\n", tool.ArtifactName)
			fmt.Printf("    Format: %s\n", tool.Format)
			fmt.Printf("    Customer ID: %s\n", tool.CustomerIdentifier)

			// Show generated naming convention
			standardName := c.GenerateArtifactNamingConvention(tool.Category, tool.ArtifactName)
			fmt.Printf("    Suggested Artifact Name: %s\n", standardName)
		}
	}

	// Print release configuration if in release mode
	if c.IsReleaseTask() {
		fmt.Printf("\n🚀 Release Readiness Assessment:\n")
		fmt.Printf("  Mode: ENABLED\n")
		fmt.Printf("  Production Branch: %s\n", c.Release.ProductionBranch)
		fmt.Printf("  Release Branch: %s\n", c.Release.ReleaseBranch)
		fmt.Printf("  Workflow Timeout: %d minutes\n", c.Release.WorkflowTimeout)

		if err := c.ValidateReleaseReadiness(); err != nil {
			fmt.Printf("  ❌ Validation Error: %s\n", err)
		} else {
			fmt.Printf("  ✅ Configuration Valid\n")
		}
	}

	fmt.Printf("\nGitHub Context:\n")
	fmt.Printf("  Repository: %s\n", c.GitHub.Repository)
	fmt.Printf("  Run ID: %s\n", c.GitHub.RunID)
	fmt.Printf("  Run Number: %s\n", c.GitHub.RunNumber)
	fmt.Printf("  Job ID: %s\n", c.GitHub.JobID)
	fmt.Printf("  SHA: %s\n", c.GitHub.SHA)
	fmt.Printf("  Ref: %s\n", c.GitHub.RefName)
	fmt.Printf("  Event: %s\n", c.GitHub.EventName)
	fmt.Printf("  Actor: %s\n", c.GitHub.Actor)
	fmt.Printf("  Workflow Ref: %s\n", c.GitHub.WorkflowRef)

	fmt.Printf("\nWorkflow Run Context (for linking sibling jobs):\n")
	context := c.GetWorkflowRunContext()
	for key, value := range context {
		fmt.Printf("  %s: %s\n", key, value)
	}

	fmt.Printf("\nArtifact Linking Strategy:\n")
	fmt.Printf("  - Use run_id (%s) to identify related jobs\n", c.GitHub.RunID)
	fmt.Printf("  - Use repository (%s) to scope artifacts\n", c.GitHub.Repository)
	fmt.Printf("  - Follow naming convention: vulnetix-{repo}-{run_id}-{category}-{name}\n")
	fmt.Printf("  - Use GitHub API to fetch artifacts from sibling jobs\n")

	fmt.Printf("\n")
}

// ValidateTask validates that the specified task is supported
func ValidateTask(task string) (TaskType, error) {
	switch TaskType(task) {
	case TaskScan, TaskRelease, TaskReport, TaskTriage:
		return TaskType(task), nil
	case "":
		return TaskScan, nil // Default to scan
	default:
		return "", fmt.Errorf("unsupported task: %s. Supported tasks: scan, release, report, triage", task)
	}
}

// IsReleaseTask returns true if the current task is release readiness assessment
func (c *VulnetixConfig) IsReleaseTask() bool {
	return c.Task == TaskRelease
}
