// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package tools contains the CLI commands for Zarf.
package tools

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/defenseunicorns/zarf/src/config/lang"
)

var toolsCmd = &cobra.Command{
	Use:     "tools",
	Aliases: []string{"t"},
	Short:   lang.CmdToolsShort,
}

// Include adds the tools command to the root command.
func Include(rootCmd *cobra.Command) {
	rootCmd.AddCommand(toolsCmd)
}

// newVersionCmd is a generic version command for tools
func newVersionCmd(name, version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Args:  cobra.NoArgs,
		Short: lang.CmdToolsVersionShort,
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Println(fmt.Sprintf("%s %s", name, version))
		},
	}
}
