// Package buildinfo carries the build-time identity of this binary to packages
// that cannot import cmd.
//
// The values are injected into cmd by ldflags at five build sites, and cmd
// copies them here during init. Packages below cmd — internal/cdx builds the
// metadata.tools entry, and it must name a real version — read them from here.
//
// The alternative was threading a version string through every constructor that
// eventually reaches a BOM, which is how four builders came to default it to the
// literal string "cli".
package buildinfo

// Version is the release this binary was built from. The default is what an
// unstamped build reports; it is a parseable version rather than a placeholder
// word, so a consumer comparing versions gets an answer instead of an error.
var (
	Version   = "0.0.0-unknown"
	Commit    = ""
	BuildDate = ""
)

// Set records the build identity. cmd calls it during init; nothing else should.
func Set(version, commit, buildDate string) {
	if version != "" {
		Version = version
	}
	Commit = commit
	BuildDate = buildDate
}
