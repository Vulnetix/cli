package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
)

// FileType represents the detected type of a file
type FileType string

const (
	FileTypeManifest  FileType = "manifest"
	FileTypeSPDX      FileType = "spdx"
	FileTypeCycloneDX FileType = "cyclonedx"
	FileTypeUnknown   FileType = "unknown"
)

// Detection confidence for content/name-detected pip requirements files.
const (
	// ConfidenceConfident: a clear requirements file — matched by name pattern or
	// by content carrying requirement syntax (version specs, --hash=, pip
	// directives). The build-or-lock gate treats these as definitive: an
	// unresolvable confident file is a fatal error.
	ConfidenceConfident = "confident"
	// ConfidenceTentative: an ambiguous file that is only bare package names. It is
	// confirmed a requirements file only by cross-checking its names against
	// installed packages; if it can't be confirmed it is silently disregarded.
	ConfidenceTentative = "tentative"
)

// ManifestInfo describes a known manifest file
type ManifestInfo struct {
	Type      string // canonical filename used as the manifest "type" parameter
	Ecosystem string
	Language  string
	IsLock    bool

	// Confidence is set only for pip requirements files detected by name pattern
	// or content (ConfidenceConfident / ConfidenceTentative). Empty for every
	// other manifest, including exact-name matches of non-requirements files.
	Confidence string
}

// DetectedFile represents a detected scannable file
type DetectedFile struct {
	Path         string
	RelPath      string // relative to scan root
	FileType     FileType
	ManifestInfo *ManifestInfo // non-nil for manifest files
	SBOMVersion  string        // e.g. "SPDX-2.3", "1.5" for CycloneDX
	Supported    bool          // whether the backend accepts this file type
}

// ManifestFiles maps known manifest filenames (exact basename) to their metadata.
var ManifestFiles = map[string]ManifestInfo{
	// ── JavaScript / Node.js ──────────────────────────────────────────────
	"package-lock.json":   {Type: "package-lock.json", Ecosystem: "npm", Language: "javascript", IsLock: true},
	"npm-shrinkwrap.json": {Type: "package-lock.json", Ecosystem: "npm", Language: "javascript", IsLock: true},
	"package.json":        {Type: "package.json", Ecosystem: "npm", Language: "javascript", IsLock: false},
	"yarn.lock":           {Type: "yarn.lock", Ecosystem: "npm", Language: "javascript", IsLock: true},
	"pnpm-lock.yaml":      {Type: "pnpm-lock.yaml", Ecosystem: "npm", Language: "javascript", IsLock: true},
	// ── Python ────────────────────────────────────────────────────────────
	"pyproject.toml":   {Type: "pyproject.toml", Ecosystem: "pypi", Language: "python", IsLock: false},
	"requirements.txt": {Type: "requirements.txt", Ecosystem: "pypi", Language: "python", IsLock: false},
	"requirements.in":  {Type: "requirements.in", Ecosystem: "pypi", Language: "python", IsLock: false},
	"setup.py":         {Type: "setup.py", Ecosystem: "pypi", Language: "python", IsLock: false},
	"setup.cfg":        {Type: "setup.cfg", Ecosystem: "pypi", Language: "python", IsLock: false},
	"Pipfile":          {Type: "Pipfile", Ecosystem: "pypi", Language: "python", IsLock: false},
	"Pipfile.lock":     {Type: "Pipfile.lock", Ecosystem: "pypi", Language: "python", IsLock: true},
	"poetry.lock":      {Type: "poetry.lock", Ecosystem: "pypi", Language: "python", IsLock: true},
	"uv.lock":          {Type: "uv.lock", Ecosystem: "pypi", Language: "python", IsLock: true},
	"pylock.toml":      {Type: "pylock.toml", Ecosystem: "pypi", Language: "python", IsLock: true},
	// ── Conda ─────────────────────────────────────────────────────────────
	"environment.yml":  {Type: "environment.yml", Ecosystem: "conda", Language: "python", IsLock: false},
	"environment.yaml": {Type: "environment.yml", Ecosystem: "conda", Language: "python", IsLock: false},
	// ── Go ────────────────────────────────────────────────────────────────
	"go.sum": {Type: "go.sum", Ecosystem: "golang", Language: "go", IsLock: true},
	"go.mod": {Type: "go.mod", Ecosystem: "golang", Language: "go", IsLock: false},
	// ── Ruby ──────────────────────────────────────────────────────────────
	"Gemfile":      {Type: "Gemfile", Ecosystem: "rubygems", Language: "ruby", IsLock: false},
	"Gemfile.lock": {Type: "Gemfile.lock", Ecosystem: "rubygems", Language: "ruby", IsLock: true},
	// ── Rust ──────────────────────────────────────────────────────────────
	"Cargo.toml": {Type: "Cargo.toml", Ecosystem: "cargo", Language: "rust", IsLock: false},
	"Cargo.lock": {Type: "Cargo.lock", Ecosystem: "cargo", Language: "rust", IsLock: true},
	// ── Java / Gradle ─────────────────────────────────────────────────────
	"pom.xml":         {Type: "pom.xml", Ecosystem: "maven", Language: "java", IsLock: false},
	"build.gradle":    {Type: "build.gradle", Ecosystem: "maven", Language: "java", IsLock: false},
	"gradle.lockfile": {Type: "gradle.lockfile", Ecosystem: "maven", Language: "java", IsLock: true},
	// ── Kotlin / Gradle ───────────────────────────────────────────────────
	"build.gradle.kts": {Type: "build.gradle.kts", Ecosystem: "maven", Language: "kotlin", IsLock: false},
	// ── PHP / Composer ────────────────────────────────────────────────────
	"composer.json": {Type: "composer.json", Ecosystem: "composer", Language: "php", IsLock: false},
	"composer.lock": {Type: "composer.lock", Ecosystem: "composer", Language: "php", IsLock: true},
	// ── .NET / NuGet ──────────────────────────────────────────────────────
	"packages.lock.json": {Type: "packages.lock.json", Ecosystem: "nuget", Language: "c#", IsLock: true},
	"packages.config":    {Type: "packages.config", Ecosystem: "nuget", Language: "c#", IsLock: false},
	"paket.dependencies": {Type: "paket.dependencies", Ecosystem: "nuget", Language: "c#", IsLock: false},
	"paket.lock":         {Type: "paket.lock", Ecosystem: "nuget", Language: "c#", IsLock: true},
	// ── Swift ─────────────────────────────────────────────────────────────
	"Package.swift":    {Type: "Package.swift", Ecosystem: "swift", Language: "swift", IsLock: false},
	"Package.resolved": {Type: "Package.resolved", Ecosystem: "swift", Language: "swift", IsLock: true},
	// ── Dart / Flutter ────────────────────────────────────────────────────
	"pubspec.yaml": {Type: "pubspec.yaml", Ecosystem: "pub", Language: "dart", IsLock: false},
	"pubspec.lock": {Type: "pubspec.lock", Ecosystem: "pub", Language: "dart", IsLock: true},
	// ── Elixir ────────────────────────────────────────────────────────────
	"mix.exs":  {Type: "mix.exs", Ecosystem: "hex", Language: "elixir", IsLock: false},
	"mix.lock": {Type: "mix.lock", Ecosystem: "hex", Language: "elixir", IsLock: true},
	// ── Scala / sbt / mill ────────────────────────────────────────────────
	"build.sbt":  {Type: "build.sbt", Ecosystem: "maven", Language: "scala", IsLock: false},
	"build.lock": {Type: "build.lock", Ecosystem: "maven", Language: "scala", IsLock: true},
	"build.sc":   {Type: "build.sc", Ecosystem: "maven", Language: "scala", IsLock: false},
	// ── Clojure (Leiningen / tools.deps / Babashka) ───────────────────────
	"project.clj": {Type: "project.clj", Ecosystem: "clojars", Language: "clojure", IsLock: false},
	"deps.edn":    {Type: "deps.edn", Ecosystem: "clojars", Language: "clojure", IsLock: false},
	"bb.edn":      {Type: "deps.edn", Ecosystem: "clojars", Language: "clojure", IsLock: false},
	// ── Docker / OCI container files ─────────────────────────────────────
	"Dockerfile":          {Type: "Dockerfile", Ecosystem: "docker", Language: "docker", IsLock: false},
	"Containerfile":       {Type: "Dockerfile", Ecosystem: "docker", Language: "docker", IsLock: false},
	"Gockerfile":          {Type: "Dockerfile", Ecosystem: "docker", Language: "docker", IsLock: false},
	"Pkgfile":             {Type: "Dockerfile", Ecosystem: "docker", Language: "docker", IsLock: false},
	"compose.yaml":        {Type: "compose.yaml", Ecosystem: "docker", Language: "docker", IsLock: false},
	"compose.yml":         {Type: "compose.yaml", Ecosystem: "docker", Language: "docker", IsLock: false},
	"docker-compose.yaml": {Type: "compose.yaml", Ecosystem: "docker", Language: "docker", IsLock: false},
	"docker-compose.yml":  {Type: "compose.yaml", Ecosystem: "docker", Language: "docker", IsLock: false},
	"podman-compose.yaml": {Type: "compose.yaml", Ecosystem: "docker", Language: "docker", IsLock: false},
	"podman-compose.yml":  {Type: "compose.yaml", Ecosystem: "docker", Language: "docker", IsLock: false},
	// ── CI/CD pipeline-as-code files ─────────────────────────────────────
	".gitlab-ci.yml":           {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".gitlab-ci.yaml":          {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".travis.yml":              {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".cirrus.yml":              {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".woodpecker.yml":          {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".woodpecker.yaml":         {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".drone.yml":               {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".drone.yaml":              {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".buddy.yml":               {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".buddy.yaml":              {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"azure-pipelines.yml":      {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"azure-pipelines.yaml":     {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"bitbucket-pipelines.yml":  {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"buildspec.yml":            {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"buildspec.yaml":           {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"cloudbuild.yml":           {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"cloudbuild.yaml":          {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"codefresh.yml":            {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"codefresh.yaml":           {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"appveyor.yml":             {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"appveyor.yaml":            {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"semaphore.yml":            {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"semaphore.yaml":           {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"wercker.yml":              {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"wercker.yaml":             {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"bitbucket-pipelines.yaml": {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".circleci.yml":            {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".cirrus.yaml":             {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".travis.yaml":             {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".semaphore.yml":           {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"bitrise.yml":              {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"codemagic.yaml":           {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"codeship-steps.yml":       {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"screwdriver.yaml":         {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"screwdriver.yml":          {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"zuul.yaml":                {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".zuul.yaml":               {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"harness.yaml":             {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"skaffold.yaml":            {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"skaffold.yml":             {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"garden.yml":               {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"render.yaml":              {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"cloud-init.yaml":          {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"user-data.yaml":           {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".gitpod.yml":              {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".gitpod.yaml":             {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"devcontainer.json":        {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".devcontainer.json":       {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"shippable.yml":            {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".prow.yaml":               {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"heroku.yml":               {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"vercel.json":              {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"netlify.toml":             {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".space.kts":               {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".build.yml":               {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	".build.yaml":              {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"Taskfile.yml":             {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"Taskfile.yaml":            {Type: "ci-pipeline", Ecosystem: "ci", Language: "ci", IsLock: false},
	"Earthfile":                {Type: "Dockerfile", Ecosystem: "ci", Language: "ci", IsLock: false},
	"Jenkinsfile":              {Type: "Jenkinsfile", Ecosystem: "ci", Language: "ci", IsLock: false},
	"Jenkinsfile.groovy":       {Type: "Jenkinsfile", Ecosystem: "ci", Language: "ci", IsLock: false},
	"Jenkinsfile.declarative":  {Type: "Jenkinsfile", Ecosystem: "ci", Language: "ci", IsLock: false},
	// Makefile-family and task-runner recipes carry the same `apt-get install …`
	// lines a CI job does, with no manifest anywhere near them.
	"Makefile":    {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	"makefile":    {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	"GNUmakefile": {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	"justfile":    {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".justfile":   {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	"Justfile":    {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	"Vagrantfile": {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	// ── Helm ──────────────────────────────────────────────────────────────
	"Chart.yaml": {Type: "Chart.yaml", Ecosystem: "helm", Language: "helm", IsLock: false},
	"Chart.yml":  {Type: "Chart.yaml", Ecosystem: "helm", Language: "helm", IsLock: false},
	// ── Registry config (private/custom registry supply-chain signal) ─────
	".npmrc":              {Type: "registry-config", Ecosystem: "npm", Language: "registry-config", IsLock: false},
	".yarnrc":             {Type: "registry-config", Ecosystem: "npm", Language: "registry-config", IsLock: false},
	".yarnrc.yml":         {Type: "registry-config", Ecosystem: "npm", Language: "registry-config", IsLock: false},
	"settings.gradle":     {Type: "registry-config", Ecosystem: "maven", Language: "registry-config", IsLock: false},
	"settings.gradle.kts": {Type: "registry-config", Ecosystem: "maven", Language: "registry-config", IsLock: false},
	// ── Bazel ─────────────────────────────────────────────────────────────
	"WORKSPACE":       {Type: "WORKSPACE", Ecosystem: "bazel", Language: "starlark", IsLock: false},
	"WORKSPACE.bazel": {Type: "WORKSPACE", Ecosystem: "bazel", Language: "starlark", IsLock: false},
	"MODULE.bazel":    {Type: "MODULE.bazel", Ecosystem: "bazel", Language: "starlark", IsLock: false},
	"BUCK":            {Type: "BUCK", Ecosystem: "buck", Language: "starlark", IsLock: false},
	"BUCK2":           {Type: "BUCK2", Ecosystem: "buck", Language: "starlark", IsLock: false},
	// ── C/C++ / Conan ─────────────────────────────────────────────────────
	"conanfile.txt": {Type: "conanfile.txt", Ecosystem: "conan", Language: "c++", IsLock: false},
	"conanfile.py":  {Type: "conanfile.py", Ecosystem: "conan", Language: "c++", IsLock: false},
	"conan.lock":    {Type: "conan.lock", Ecosystem: "conan", Language: "c++", IsLock: true},
	// ── C/C++ / vcpkg ─────────────────────────────────────────────────────
	"vcpkg.json": {Type: "vcpkg.json", Ecosystem: "vcpkg", Language: "c++", IsLock: false},
	// ── CocoaPods (iOS/macOS) ─────────────────────────────────────────────
	"Podfile":      {Type: "Podfile", Ecosystem: "cocoapods", Language: "swift", IsLock: false},
	"Podfile.lock": {Type: "Podfile.lock", Ecosystem: "cocoapods", Language: "swift", IsLock: true},
	// ── Carthage (iOS/macOS) ──────────────────────────────────────────────
	"Cartfile":          {Type: "Cartfile", Ecosystem: "carthage", Language: "swift", IsLock: false},
	"Cartfile.resolved": {Type: "Cartfile.resolved", Ecosystem: "carthage", Language: "swift", IsLock: true},
	// ── Julia ─────────────────────────────────────────────────────────────
	"Project.toml":  {Type: "Project.toml", Ecosystem: "julia", Language: "julia", IsLock: false},
	"Manifest.toml": {Type: "Manifest.toml", Ecosystem: "julia", Language: "julia", IsLock: true},
	// ── Crystal ───────────────────────────────────────────────────────────
	"shard.yml":  {Type: "shard.yml", Ecosystem: "crystal", Language: "crystal", IsLock: false},
	"shard.lock": {Type: "shard.lock", Ecosystem: "crystal", Language: "crystal", IsLock: true},
	// ── Deno ──────────────────────────────────────────────────────────────
	"deno.json": {Type: "deno.json", Ecosystem: "deno", Language: "typescript", IsLock: false},
	"deno.lock": {Type: "deno.lock", Ecosystem: "deno", Language: "typescript", IsLock: true},
	// ── R / CRAN ──────────────────────────────────────────────────────────
	"DESCRIPTION": {Type: "DESCRIPTION", Ecosystem: "cran", Language: "r", IsLock: false},
	"renv.lock":   {Type: "renv.lock", Ecosystem: "cran", Language: "r", IsLock: true},
	// ── Erlang / rebar3 ───────────────────────────────────────────────────
	"rebar.config": {Type: "rebar.config", Ecosystem: "erlang", Language: "erlang", IsLock: false},
	"rebar.lock":   {Type: "rebar.lock", Ecosystem: "erlang", Language: "erlang", IsLock: true},
	// ── Haskell / Stack ───────────────────────────────────────────────────
	"stack.yaml": {Type: "stack.yaml", Ecosystem: "stack", Language: "haskell", IsLock: false},
	// ── Haskell / Cabal ───────────────────────────────────────────────────
	"cabal.project.freeze": {Type: "cabal.project.freeze", Ecosystem: "cabal", Language: "haskell", IsLock: true},
	// ── OCaml / opam (exact filename) ────────────────────────────────────
	"opam": {Type: "opam", Ecosystem: "opam", Language: "ocaml", IsLock: false},
	// ── Nix ───────────────────────────────────────────────────────────────
	"flake.nix":  {Type: "flake.nix", Ecosystem: "nix", Language: "nix", IsLock: false},
	"flake.lock": {Type: "flake.lock", Ecosystem: "nix", Language: "nix", IsLock: true},
	// ── Zig ───────────────────────────────────────────────────────────────
	"build.zig.zon": {Type: "build.zig.zon", Ecosystem: "zig", Language: "zig", IsLock: false},
	// ── CMake / CPM ───────────────────────────────────────────────────────
	"CPM.cmake": {Type: "CPM.cmake", Ecosystem: "cpm", Language: "cmake", IsLock: false},
	// ── Meson ─────────────────────────────────────────────────────────────
	"meson.build": {Type: "meson.build", Ecosystem: "meson", Language: "c", IsLock: false},
}

// ManifestExtensions maps file extensions to manifest metadata.
// Used for files whose names include a project-specific prefix (e.g. foo.csproj, main.tf).
var ManifestExtensions = map[string]ManifestInfo{
	".csproj":        {Type: "*.csproj", Ecosystem: "nuget", Language: "c#", IsLock: false},
	".fsproj":        {Type: "*.csproj", Ecosystem: "nuget", Language: "f#", IsLock: false},
	".vbproj":        {Type: "*.csproj", Ecosystem: "nuget", Language: "vb", IsLock: false},
	".tf":            {Type: "*.tf", Ecosystem: "terraform", Language: "hcl", IsLock: false},
	".opam":          {Type: "*.opam", Ecosystem: "opam", Language: "ocaml", IsLock: false},
	".cabal":         {Type: "*.cabal", Ecosystem: "cabal", Language: "haskell", IsLock: false},
	".dockerfile":    {Type: "Dockerfile", Ecosystem: "docker", Language: "docker", IsLock: false},
	".containerfile": {Type: "Dockerfile", Ecosystem: "docker", Language: "docker", IsLock: false},
	".sh":            {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".bash":          {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".zsh":           {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".ksh":           {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".bats":          {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".ash":           {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".dash":          {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".fish":          {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".command":       {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".mk":            {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	// Windows shells install packages in CI too (choco/scoop/winget), and the
	// install-command parser understands those commands.
	".ps1":  {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".psm1": {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".cmd":  {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
	".bat":  {Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false},
}

// SupportedManifestTypes lists manifest types that have a local parser implemented.
// Files detected but absent from this map are shown as "[not supported]" in scan output.
var SupportedManifestTypes = map[string]bool{
	// JavaScript / Node.js
	"package.json":      true,
	"package-lock.json": true,
	"yarn.lock":         true,
	"pnpm-lock.yaml":    true,
	// Python
	"pyproject.toml":   true,
	"requirements.txt": true,
	"requirements.in":  true,
	"setup.py":         true,
	"setup.cfg":        true,
	"Pipfile":          true,
	"Pipfile.lock":     true,
	"poetry.lock":      true,
	"uv.lock":          true,
	"pylock.toml":      true,
	// Conda
	"environment.yml": true,
	// Go
	"go.sum": true,
	"go.mod": true,
	// Ruby
	"Gemfile":      true,
	"Gemfile.lock": true,
	// Rust
	"Cargo.toml": true,
	"Cargo.lock": true,
	// Java / Gradle
	"pom.xml":          true,
	"build.gradle":     true,
	"gradle.lockfile":  true,
	"build.gradle.kts": true,
	// PHP / Composer
	"composer.json": true,
	"composer.lock": true,
	// .NET / NuGet
	"packages.lock.json": true,
	"packages.config":    true,
	"paket.dependencies": true,
	"paket.lock":         true,
	"*.csproj":           true,
	// Clojure (Leiningen / tools.deps / Babashka)
	"project.clj": true,
	"deps.edn":    true,
	// Swift
	"Package.swift":    true,
	"Package.resolved": true,
	// Dart / Flutter
	"pubspec.yaml": true,
	"pubspec.lock": true,
	// Elixir
	"mix.exs":  true,
	"mix.lock": true,
	// Scala / sbt / mill
	"build.sbt":  true,
	"build.lock": true,
	"build.sc":   true,
	// Docker / OCI container files
	"Dockerfile":   true,
	"compose.yaml": true,
	// Kubernetes / Helm (container image extraction)
	"kubernetes.yaml": true,
	"Chart.yaml":      true,
	// Terraform
	"*.tf": true,
	// GitHub Actions
	"github-actions.yml": true,
	// CI/CD pipeline-as-code and shell install commands
	"ci-pipeline":  true,
	"Jenkinsfile":  true,
	"shell-script": true,
	// C/C++ / Conan
	"conanfile.txt": true,
	"conanfile.py":  true,
	"conan.lock":    true,
	// C/C++ / vcpkg
	"vcpkg.json": true,
	// CocoaPods
	"Podfile":      true,
	"Podfile.lock": true,
	// Carthage
	"Cartfile":          true,
	"Cartfile.resolved": true,
	// Julia
	"Project.toml":  true,
	"Manifest.toml": true,
	// Crystal
	"shard.yml":  true,
	"shard.lock": true,
	// Deno
	"deno.json": true,
	"deno.lock": true,
	// R / CRAN
	"DESCRIPTION": true,
	"renv.lock":   true,
	// Erlang / rebar3
	"rebar.config": true,
	"rebar.lock":   true,
	// Haskell / Stack
	"stack.yaml": true,
	// Haskell / hpack
	"package.yaml": true, // content-checked: only detected when the file is an hpack description
	// Haskell / Cabal
	"*.cabal":              true,
	"cabal.project.freeze": true,
	// OCaml / opam
	"*.opam": true,
	"opam":   true,
	// Nix
	"flake.nix":  true,
	"flake.lock": true,
	// Zig
	"build.zig.zon": true,
	// Meson
	"meson.build": true,
	// Bazel
	"WORKSPACE":    true,
	"MODULE.bazel": true,
	// Buck
	"BUCK":  true,
	"BUCK2": true,
	// CMake / CPM
	"CPM.cmake":      true,
	"CMakeLists.txt": true, // content-checked: only detected when file contains CPMAddPackage
}

// DetectManifest checks if a file is a known manifest.
// It checks in order: exact basename → file extension → path pattern (GitHub Actions).
func DetectManifest(filename string) (*ManifestInfo, bool) {
	base := filepath.Base(filename)
	lowerBase := strings.ToLower(base)

	// 1. Exact basename match.
	if info, ok := ManifestFiles[base]; ok {
		// Exact requirements files are unambiguously requirements files.
		if info.Type == "requirements.txt" || info.Type == "requirements.in" {
			info.Confidence = ConfidenceConfident
		}
		return &info, true
	}

	// 2. Name-variant match for Dockerfile / Containerfile families.
	if strings.Contains(lowerBase, "dockerfile") || strings.Contains(lowerBase, "containerfile") {
		info := ManifestInfo{
			Type:      "Dockerfile",
			Ecosystem: "docker",
			Language:  "docker",
			IsLock:    false,
		}
		return &info, true
	}

	// 3. Extension-based match (e.g. foo.csproj, main.tf, mylib.opam, myapp.cabal).
	ext := strings.ToLower(filepath.Ext(base))
	if info, ok := ManifestExtensions[ext]; ok {
		// Avoid matching obviously wrong files (e.g. a random .tf that isn't Terraform).
		// All extension matches are considered valid — the parser handles false positives.
		infoCopy := info
		return &infoCopy, true
	}

	// 3a. Pip requirements files with non-standard names, matched by name pattern
	// (requirements-dev.txt, requirements/base.in, constraints.txt, foo.pip, …).
	// String-only — no file read.
	if looksLikeRequirementsName(filename) {
		return &ManifestInfo{Type: "requirements.txt", Ecosystem: "pypi", Language: "python", IsLock: false, Confidence: ConfidenceConfident}, true
	}

	// 4. Content-checked: CMakeLists.txt with CPMAddPackage calls.
	if base == "CMakeLists.txt" {
		content, err := os.ReadFile(filename)
		if err == nil && strings.Contains(string(content), "CPMAddPackage") {
			info := ManifestInfo{
				Type:      "CMakeLists.txt",
				Ecosystem: "cpm",
				Language:  "cmake",
				IsLock:    false,
			}
			return &info, true
		}
	}

	// 4a. Content-checked: hpack's package.yaml. hpack generates the .cabal file
	// from it, so on a stack project it holds the only declaration of the
	// package's dependencies. The name is generic enough to belong to other
	// tools, so it counts only when the file carries an hpack section.
	if base == "package.yaml" && looksLikeHpackYAML(filename) {
		info := ManifestInfo{
			Type:      "package.yaml",
			Ecosystem: "hackage",
			Language:  "haskell",
			IsLock:    false,
		}
		return &info, true
	}

	// 5. Content-checked: compose-compatible YAML files with service image/build keys.
	if strings.HasSuffix(lowerBase, ".yml") || strings.HasSuffix(lowerBase, ".yaml") {
		content, err := os.ReadFile(filename)
		if err == nil && looksLikeComposeYAML(string(content)) {
			info := ManifestInfo{
				Type:      "compose.yaml",
				Ecosystem: "docker",
				Language:  "docker",
				IsLock:    false,
			}
			return &info, true
		}

		// 5a. Content-checked: Kubernetes manifests (apiVersion + kind). Runs after
		// the compose check so a docker-compose file is never misread as k8s.
		if content, err := os.ReadFile(filename); err == nil && looksLikeKubernetesYAML(string(content)) {
			info := ManifestInfo{
				Type:      "kubernetes.yaml",
				Ecosystem: "kubernetes",
				Language:  "kubernetes",
				IsLock:    false,
			}
			return &info, true
		}

		// 6. Path-pattern: GitHub Actions and the forks that reuse its syntax
		// (Gitea, Forgejo), plus composite/reusable action definitions. These are
		// routed to the Actions parser rather than the generic CI parser so
		// `uses:` pins are resolved as github-actions packages, not just the
		// install commands inside `run:` steps.
		if looksLikeGitHubActionsPath(filename) {
			info := ManifestInfo{
				Type:      "github-actions.yml",
				Ecosystem: "github-actions",
				Language:  "yaml",
				IsLock:    false,
			}
			return &info, true
		}
	}

	// 6a. Path-pattern: pipeline-as-code files for every other CI system. Runs
	// after the compose/Kubernetes/Actions checks so a compose file that happens
	// to live in `ci/` keeps its more specific classification.
	if looksLikeCIPipelinePath(filename) {
		info := ManifestInfo{
			Type:      "ci-pipeline",
			Ecosystem: "ci",
			Language:  "ci",
			IsLock:    false,
		}
		return &info, true
	}

	if looksLikeShellScript(filename, lowerBase) {
		return &ManifestInfo{Type: "shell-script", Ecosystem: "shell", Language: "shell", IsLock: false}, true
	}

	// 7. Content-checked: arbitrarily-named pip requirements files. Gated to small
	// .txt/.in/.pip/extensionless files and run last, so cheaper rules win first.
	if conf := classifyRequirementsContent(filename, lowerBase); conf != "" {
		return &ManifestInfo{Type: "requirements.txt", Ecosystem: "pypi", Language: "python", IsLock: false, Confidence: conf}, true
	}

	return nil, false
}

// looksLikeKubernetesYAML reports whether a YAML document (or multi-document
// stream) carries the top-level apiVersion + kind keys that mark a Kubernetes
// manifest. It scans line-anchored, so `apiVersion:`/`kind:` nested inside a
// compose or CRD-spec block do not false-positive. Helm Chart.yaml is excluded
// (it is matched earlier by exact name) and Helm templates that are fully
// Go-templated at the top level are skipped (no literal apiVersion line).
func looksLikeKubernetesYAML(content string) bool {
	hasAPIVersion := false
	hasKind := false
	for _, ln := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(ln)
		// Only top-level keys (no indentation) count.
		if trimmed != ln {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "apiVersion:"):
			hasAPIVersion = true
		case strings.HasPrefix(trimmed, "kind:"):
			// Ignore docker-compose's own (rare) keys and Chart.yaml.
			hasKind = true
		}
		if hasAPIVersion && hasKind {
			return true
		}
	}
	return false
}

// looksLikeHpackYAML reports whether a package.yaml is an hpack package
// description: it declares dependencies and carries at least one of the
// component/build sections hpack defines.
func looksLikeHpackYAML(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil || info.IsDir() || info.Size() > 256*1024 {
		return false
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return false
	}
	hasDeps := false
	hasSection := false
	for _, ln := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(trimmed, "dependencies:"), strings.HasPrefix(trimmed, "build-depends:"):
			hasDeps = true
		case strings.HasPrefix(trimmed, "library:"), strings.HasPrefix(trimmed, "executable:"),
			strings.HasPrefix(trimmed, "executables:"), strings.HasPrefix(trimmed, "internal-libraries:"),
			strings.HasPrefix(trimmed, "spec-version:"), strings.HasPrefix(trimmed, "ghc-options:"),
			strings.HasPrefix(trimmed, "default-extensions:"):
			hasSection = true
		}
		if hasDeps && hasSection {
			return true
		}
	}
	return false
}

func looksLikeComposeYAML(content string) bool {
	lower := strings.ToLower(content)
	if !strings.Contains(lower, "services:") {
		return false
	}
	return strings.Contains(lower, "\n    image:") ||
		strings.Contains(lower, "\n  image:") ||
		strings.Contains(lower, "\n    build:") ||
		strings.Contains(lower, "\n  build:")
}

// looksLikeRequirementsName reports whether a filename matches a common pip
// requirements/constraints naming convention (without reading the file).
func looksLikeRequirementsName(filename string) bool {
	base := strings.ToLower(filepath.Base(filename))
	ext := filepath.Ext(base)
	if ext == ".pip" {
		return true
	}
	if ext == ".txt" || ext == ".in" {
		stem := strings.TrimSuffix(base, ext)
		if strings.Contains(stem, "requirements") || strings.Contains(stem, "constraints") {
			return true
		}
		switch strings.ToLower(filepath.Base(filepath.Dir(filename))) {
		case "requirements", "requires":
			return true
		}
	}
	return false
}

// ciPipelineDirs are the directories CI systems keep pipeline-as-code in. A YAML
// (or extensionless `config`) file inside one is treated as a pipeline, because
// the install commands in it put packages on the build machine with no manifest
// to declare them.
var ciPipelineDirs = []string{
	".circleci", ".buildkite", ".semaphore", ".teamcity", ".woodpecker", ".drone",
	".azure", ".azure-pipelines", ".pipelines", ".ci", "ci", ".gitlab/ci", ".gitlab-ci",
	".tekton", "tekton", ".argo", ".argo-workflows", ".concourse", "concourse",
	".harness", "bamboo-specs", ".cirrus", ".codefresh", ".buddy", ".zuul.d",
	".prow", "prow", ".builds", ".dagger", ".jenkins", ".spinnaker", ".screwdriver",
	".bitbucket", ".codeship", ".devcontainer", ".earthly", ".garden", ".skaffold",
	".gocd", ".appveyor", ".bitrise", ".codemagic", ".travis", ".nomad", ".gitpod",
}

// ciPipelineNameSuffixes catch pipeline files that live outside a CI directory,
// including GitLab CI templates (`security.gitlab-ci.yml`) and the
// `*-pipeline.yml` convention used by Concourse, Tekton and Argo.
var ciPipelineNameSuffixes = []string{
	"/pipeline.yml", "/pipeline.yaml", "/pipelines.yml", "/pipelines.yaml",
	"/ci.yml", "/ci.yaml", "-pipeline.yml", "-pipeline.yaml",
	"-pipelines.yml", "-pipelines.yaml",
	".gitlab-ci.yml", ".gitlab-ci.yaml",
	"/workflow.yml", "/workflow.yaml", "-workflow.yml", "-workflow.yaml",
	"/.build.yml", "/.build.yaml",
}

func looksLikeCIPipelinePath(filename string) bool {
	slash := strings.ToLower(filepath.ToSlash(filename))
	// Inside a CI directory the DSL varies by vendor: YAML for most, JSON for
	// devcontainers, Kotlin for TeamCity and JetBrains Space, Groovy for Jenkins,
	// and an extensionless `config` for older CircleCI layouts. Non-YAML files fall
	// back to line-oriented shell parsing, which is what those DSLs embed anyway.
	ciExt := strings.HasSuffix(slash, ".yml") || strings.HasSuffix(slash, ".yaml") ||
		strings.HasSuffix(slash, ".json") || strings.HasSuffix(slash, "/config") ||
		strings.HasSuffix(slash, ".kts") || strings.HasSuffix(slash, ".groovy")
	if !ciExt {
		return false
	}
	for _, dir := range ciPipelineDirs {
		if strings.Contains(slash, "/"+dir+"/") || strings.HasPrefix(slash, dir+"/") {
			return true
		}
	}
	// A bare .json/.kts/.groovy outside a CI directory is almost never a pipeline;
	// only the directory rule above (which covers .devcontainer/devcontainer.json)
	// and the exact-name table apply.
	if strings.HasSuffix(slash, ".json") || strings.HasSuffix(slash, ".kts") || strings.HasSuffix(slash, ".groovy") {
		return false
	}
	for _, suffix := range ciPipelineNameSuffixes {
		if strings.HasSuffix(slash, suffix) {
			return true
		}
	}
	return false
}

// IsCIPipelineFile reports whether a detected manifest is pipeline-as-code.
// GitHub Actions workflows are counted: they are CI files whose `run:` steps
// install packages, so `--no-ci` style flags must reach them too, even though
// their `uses:` pins are also resolved as github-actions packages.
func IsCIPipelineFile(info *ManifestInfo) bool {
	if info == nil {
		return false
	}
	return info.Language == "ci" || info.Ecosystem == "ci" || info.Ecosystem == "github-actions"
}

// looksLikeGitHubActionsPath reports whether a YAML file is a GitHub Actions
// workflow, a Gitea/Forgejo workflow (same schema, same `uses:` pins), or a
// composite/reusable action definition.
func looksLikeGitHubActionsPath(filename string) bool {
	slash := strings.ToLower(filepath.ToSlash(filename))
	base := slash
	if i := strings.LastIndexByte(slash, '/'); i >= 0 {
		base = slash[i+1:]
	}
	if base == "action.yml" || base == "action.yaml" {
		return true
	}
	for _, dir := range []string{
		".github/workflows/", ".github/actions/",
		".gitea/workflows/", ".forgejo/workflows/",
	} {
		if strings.Contains(slash, "/"+dir) || strings.HasPrefix(slash, dir) {
			return true
		}
	}
	return false
}

func looksLikeShellScript(filename, lowerBase string) bool {
	if filepath.Ext(lowerBase) != "" {
		return false
	}
	info, err := os.Stat(filename)
	if err != nil || info.IsDir() || info.Size() > 256*1024 {
		return false
	}
	f, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 256)
	n, _ := f.Read(buf)
	first := strings.TrimSpace(string(buf[:n]))
	return strings.HasPrefix(first, "#!/bin/sh") ||
		strings.HasPrefix(first, "#!/usr/bin/env sh") ||
		strings.HasPrefix(first, "#!/bin/bash") ||
		strings.HasPrefix(first, "#!/usr/bin/env bash") ||
		strings.HasPrefix(first, "#!/bin/zsh") ||
		strings.HasPrefix(first, "#!/usr/bin/env zsh")
}

// Per-line shape tests for pip requirements content.
var (
	reqVersionedLine = regexp.MustCompile(`^[A-Za-z0-9._-]+(\[[A-Za-z0-9,._-]+\])?\s*(===|==|>=|<=|~=|!=|>|<)\s*\S`)
	reqURLRefLine    = regexp.MustCompile(`^[A-Za-z0-9._-]+\s*@\s+\S`)
	reqBareNameLine  = regexp.MustCompile(`^[A-Za-z0-9._-]+(\[[A-Za-z0-9,._-]+\])?$`)
)

// reqCandidateExts gates which files get a content sniff for pip requirements.
// It covers plausible requirements/constraints/text-list extensions plus
// extensionless files, while excluding source-code/binary extensions so the
// walker doesn't read every file in the tree. (Source files would be rejected by
// the classifier anyway; the gate just avoids the I/O.)
var reqCandidateExts = map[string]bool{
	"":              true,
	".txt":          true,
	".in":           true,
	".pip":          true,
	".reqs":         true,
	".requirements": true,
	".list":         true,
	".lst":          true,
	".text":         true,
}

// classifyRequirementsContent reads a small prefix of a plausible file and
// classifies it as a pip requirements file. Returns ConfidenceConfident,
// ConfidenceTentative, or "" (not a requirements file). Gated by extension and
// size to bound the I/O the walker incurs.
func classifyRequirementsContent(filename, lowerBase string) string {
	if !reqCandidateExts[filepath.Ext(lowerBase)] {
		return ""
	}
	info, err := os.Stat(filename)
	if err != nil || info.IsDir() || info.Size() > 256*1024 {
		return ""
	}
	f, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	s := string(buf[:n])
	// Drop a possibly-truncated final line when the prefix filled the buffer.
	if n == len(buf) {
		if idx := strings.LastIndex(s, "\n"); idx >= 0 {
			s = s[:idx]
		}
	}
	return classifyRequirementsText(s)
}

// classifyRequirementsText classifies already-read text. confident when a line
// carries requirement syntax (version op, --hash=, URL ref, or a pip directive);
// tentative when every meaningful line is a bare package name; "" as soon as any
// line cannot be a requirement (so prose, wordlists with paths, gitignores, etc.
// are rejected).
func classifyRequirementsText(content string) string {
	confident := false
	sawName := false
	for _, ln := range strings.Split(content, "\n") {
		line := strings.TrimSpace(ln)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			if hasPipDirective(line) {
				confident = true
				continue
			}
			return ""
		}
		// Strip an inline comment.
		if ci := strings.Index(line, " #"); ci >= 0 {
			line = strings.TrimSpace(line[:ci])
		}
		hadHash := strings.Contains(line, "--hash=")
		if hadHash {
			var keep []string
			for _, fld := range strings.Fields(line) {
				if strings.HasPrefix(fld, "--hash=") {
					continue
				}
				keep = append(keep, fld)
			}
			line = strings.Join(keep, " ")
		}
		spec := line
		if i := strings.Index(spec, ";"); i >= 0 {
			spec = strings.TrimSpace(spec[:i])
		}
		switch {
		case reqVersionedLine.MatchString(spec) || reqURLRefLine.MatchString(spec):
			confident, sawName = true, true
		case reqBareNameLine.MatchString(spec):
			sawName = true
			if hadHash {
				confident = true // pinned by hash → not ambiguous
			}
		default:
			return "" // not a requirement line
		}
	}
	switch {
	case confident:
		return ConfidenceConfident
	case sawName:
		return ConfidenceTentative
	default:
		return ""
	}
}

// hasPipDirective reports whether a line is a pip requirements directive/option.
func hasPipDirective(line string) bool {
	for _, d := range []string{
		"-r", "-c", "-e", "-i", "-f",
		"--requirement", "--constraint", "--editable", "--index-url",
		"--extra-index-url", "--find-links", "--hash", "--no-binary",
		"--only-binary", "--pre", "--no-index", "--trusted-host",
	} {
		if line == d || strings.HasPrefix(line, d+" ") || strings.HasPrefix(line, d+"=") {
			return true
		}
	}
	return false
}

// DetectSBOM reads the first bytes of a JSON file and determines if it's an SPDX or CycloneDX document.
// Returns the file type, version string, and whether it's valid/supported.
func DetectSBOM(filePath string) (FileType, string, bool) {
	if !strings.HasSuffix(strings.ToLower(filePath), ".json") {
		return FileTypeUnknown, "", false
	}

	f, err := os.Open(filePath)
	if err != nil {
		return FileTypeUnknown, "", false
	}
	defer f.Close()

	// Read first 4KB
	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return FileTypeUnknown, "", false
	}

	// Try to parse as JSON
	var data map[string]interface{}
	if err := json.Unmarshal(buf[:n], &data); err != nil {
		// Try with the full file if the first 4KB wasn't valid JSON
		fullData, err2 := os.ReadFile(filePath)
		if err2 != nil {
			return FileTypeUnknown, "", false
		}
		if err := json.Unmarshal(fullData, &data); err != nil {
			return FileTypeUnknown, "", false
		}
	}

	// Check for SPDX: has spdxVersion AND SPDXID fields
	if spdxVersion, ok := data["spdxVersion"].(string); ok {
		if _, hasID := data["SPDXID"]; hasID {
			supported := spdxVersion == "SPDX-2.3"
			return FileTypeSPDX, spdxVersion, supported
		}
	}

	// Check for CycloneDX: has bomFormat == "CycloneDX" AND specVersion
	if bomFormat, ok := data["bomFormat"].(string); ok && bomFormat == "CycloneDX" {
		if specVersion, ok := data["specVersion"].(string); ok {
			// Validate against embedded schemas (highest version first, short-circuit).
			fullData, readErr := os.ReadFile(filePath)
			if readErr != nil {
				return FileTypeCycloneDX, specVersion, false
			}
			validatedVersion, violations, valErr := cyclonedx.ValidateCycloneDX(fullData)
			if valErr != nil || len(violations) > 0 || validatedVersion == "" {
				return FileTypeCycloneDX, specVersion, false
			}
			return FileTypeCycloneDX, validatedVersion, true
		}
	}

	return FileTypeUnknown, "", false
}
