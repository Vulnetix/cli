package cmd

import "fmt"

// CommandAcceptsFlag reports whether the command at path (the arguments after
// `vulnetix`, subcommands only, for example {"gha", "publish", "campaigns"})
// defines the flag, given without its leading dashes. It exists for
// tools/actiongen, which checks that every flag a generated GitHub Action
// passes is one the command accepts.
func CommandAcceptsFlag(path []string, flag string) (bool, error) {
	c, rest, err := rootCmd.Find(path)
	if err != nil {
		return false, err
	}
	if len(rest) > 0 {
		return false, fmt.Errorf("no command %q", path)
	}
	return c.Flag(flag) != nil, nil
}
