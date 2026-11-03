package cmd

import (
	"strconv"
	"sync"

	"github.com/vulnetix/cli/v4/internal/ghactx"
	"github.com/vulnetix/cli/v4/internal/gitctx"
	"github.com/vulnetix/cli/v4/internal/triage"
	"github.com/vulnetix/cli/v4/pkg/auth"
	"github.com/vulnetix/cli/v4/pkg/vdb"
)

// Identity evidence on every /v2/cli.* request. The server decides who acted
// from a ladder (key principal, GitHub Actions OIDC, then these claims); the
// CLI only reports what it can read and never sends a token in the body.

func init() {
	vdb.GHAOIDCToken = ghactx.OIDCToken
	triage.AccountActor = signedInAccountActor
}

// storedCredentials loads the saved credentials once, for commands that never
// resolved them (a local triage run, the TUI).
var storedCredentials = sync.OnceValue(func() *auth.Credentials {
	c, _ := auth.LoadCredentials()
	return c
})

// signedInAccountActor is the account a decision is attributed to when the
// CLI is signed in: vulnetix:<account id>, the VdbOrganization the key belongs
// to (a person for a device-login key). "" when there is no account to name:
// no credentials, the embedded community key, or a token whose account only
// the server can resolve. Then the decision falls back to git config or
// user@host.
func signedInAccountActor() string {
	c := vdbCreds
	if c == nil {
		c = storedCredentials()
	}
	return accountActorFor(c)
}

func accountActorFor(c *auth.Credentials) string {
	if c == nil || c.OrgID == "" || auth.IsCommunity(c) || c.OrgID == auth.CommunityOrgID {
		return ""
	}
	return "vulnetix:" + c.OrgID
}

// cliIdentity collects the claimed identity for a request: git config for the
// scanned repository, the HEAD commit's author, the OS account and host, and
// the GitHub Actions actor when ci is set. Nil when nothing could be read.
func cliIdentity(git *gitctx.GitContext, sys *gitctx.SystemInfo, ci *vdb.CliCIContext) *vdb.CliIdentity {
	id := &vdb.CliIdentity{}
	dir := ""
	if git != nil {
		dir = git.RepoRootPath
		id.HeadAuthorName = git.HeadCommitAuthor
		id.HeadAuthorEmail = git.HeadCommitEmail
	}
	cfg := gitctx.ConfigUser(dir)
	id.GitConfigName, id.GitConfigEmail = cfg.Name, cfg.Email
	if sys != nil {
		id.OSUser = sys.Username
		id.Hostname = sys.Hostname
	}
	if ci != nil {
		id.CIProvider = ci.Provider
		id.CIActor = ci.Actor
		id.CITriggeringActor = ci.TriggeringActor
		id.CIRepository = ci.Repository
		if ci.RunID > 0 {
			id.CIRunID = strconv.FormatInt(ci.RunID, 10)
		}
		id.CISha = ci.SHA
	}
	if *id == (vdb.CliIdentity{}) {
		return nil
	}
	return id
}
