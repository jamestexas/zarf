// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package lint contains functions for verifying zarf yaml files are valid
package lint

import (
	"fmt"
	"path/filepath"

	"github.com/defenseunicorns/pkg/helpers/v2"
	"github.com/defenseunicorns/zarf/src/pkg/message"
	"github.com/defenseunicorns/zarf/src/types"
	"github.com/fatih/color"
)

func itemizedDescription(description string, item string) string {
	if item == "" {
		return description
	}
	return fmt.Sprintf("%s - %s", description, item)
}

func colorWrapSev(s types.Severity) string {
	if s == types.SevErr {
		return message.ColorWrap("Error", color.FgRed)
	} else if s == types.SevWarn {
		return message.ColorWrap("Warning", color.FgYellow)
	}
	return "unknown"
}

func packageRelPathToUser(baseDir string, relPath string) string {
	if helpers.IsOCIURL(relPath) {
		return relPath
	}
	return filepath.Join(baseDir, relPath)
}

// PrintFindings prints a table of the findings with the given severity or higher
func PrintFindings(findings []types.PackageError, severity types.Severity, baseDir string, packageName string) {
	if !hasSeverity(findings, severity) {
		return
	}

	mapOfFindingsByPath := groupFindingsByPath(findings, severity, packageName)

	header := []string{"Type", "Path", "Message"}

	for _, findings := range mapOfFindingsByPath {
		lintData := [][]string{}
		for _, finding := range findings {
			lintData = append(lintData, []string{
				colorWrapSev(finding.Category),
				pathColorWrap(finding.YqPath),
				itemizedDescription(finding.Description, finding.Item),
			})
		}
		message.Notef("Linting package %q at %s", findings[0].PackageNameOverride,
			packageRelPathToUser(baseDir, findings[0].PackagePathOverride))
		message.Table(header, lintData)
	}
}

func groupFindingsByPath(findings []types.PackageError, severity types.Severity, packageName string) map[string][]types.PackageError {
	findings = helpers.RemoveMatches(findings, func(finding types.PackageError) bool {
		return finding.Category > severity
	})
	for i := range findings {
		if findings[i].PackageNameOverride == "" {
			findings[i].PackageNameOverride = packageName
		}
		if findings[i].PackagePathOverride == "" {
			findings[i].PackagePathOverride = "."
		}
	}

	mapOfFindingsByPath := make(map[string][]types.PackageError)
	for _, finding := range findings {
		mapOfFindingsByPath[finding.PackagePathOverride] = append(mapOfFindingsByPath[finding.PackagePathOverride], finding)
	}
	return mapOfFindingsByPath
}

func pathColorWrap(path string) string {
	if path == "" {
		return ""
	}
	return message.ColorWrap(path, color.FgCyan)
}

func hasSeverity(findings []types.PackageError, category types.Severity) bool {
	for _, finding := range findings {
		if finding.Category <= category {
			return true
		}
	}
	return false
}

// HasErrors returns true if the validator finds errors in the Zarf package
func HasErrors(findings []types.PackageError) bool {
	return hasSeverity(findings, types.SevErr)
}
