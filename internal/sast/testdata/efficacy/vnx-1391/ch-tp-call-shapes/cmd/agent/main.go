package main

import "github.com/spf13/cobra"

var pw string

func flags(cmd *cobra.Command) {
~>	cmd.Flags().StringVarP(&pw, "password", "p", "123456", "agent password")
}
