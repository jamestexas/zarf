// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package rules verifies that Zarf packages are following best practices
package rules

import (
	"fmt"
	"path/filepath"

	"github.com/defenseunicorns/pkg/helpers/v2"
	"github.com/defenseunicorns/zarf/src/pkg/message"
	"github.com/fatih/color"
)

// PackageFinding is a struct that contains a finding about something wrong with a package
type PackageFinding struct {
	// YqPath is the path to the key where the error originated from, this is sometimes empty in the case of a general error
	YqPath      string
	Description string
	// Item is the value of a key that is causing an error, for example a bad image name
	Item string
	// PackageNameOverride shows the name of the package that the error originated from
	// If it is not set the base package will be used when displaying the error
	PackageNameOverride string
	// PackagePathOverride shows the path to the package that the error originated from
	// If it is not set the base package will be used when displaying the error
	PackagePathOverride string
	Severity            Severity
}

// Severity is the type of package error
// Either Err or Warning
type Severity int

// different severities of package errors
const (
	SevErr Severity = iota + 1
	SevWarn
)

func (f PackageFinding) itemizedDescription() string {
	if f.Item == "" {
		return f.Description
	}
	return fmt.Sprintf("%s - %s", f.Description, f.Item)
}

func colorWrapSev(s Severity) string {
	if s == SevErr {
		return message.ColorWrap("Error", color.FgRed)
	} else if s == SevWarn {
		return message.ColorWrap("Warning", color.FgYellow)
	}
	return "unknown"
}

// PrintFindings prints the findings of the given severity in a table
func PrintFindings(findings []PackageFinding, severity Severity, baseDir string, packageName string) {
	// TODO add filter sev function
	mapOfFindingsByPath := GroupFindingsByPath(findings, severity, packageName)
	if len(mapOfFindingsByPath) == 0 {
		return
	}

	header := []string{"Type", "Path", "Message"}

	for _, findings := range mapOfFindingsByPath {
		lintData := [][]string{}
		for _, finding := range findings {
			lintData = append(lintData, []string{
				colorWrapSev(finding.Severity),
				message.ColorWrap(finding.YqPath, color.FgCyan),
				finding.itemizedDescription(),
			})
		}
		var packagePathFromUser string
		if helpers.IsOCIURL(findings[0].PackagePathOverride) {
			packagePathFromUser = findings[0].PackagePathOverride
		} else {
			packagePathFromUser = filepath.Join(baseDir, findings[0].PackagePathOverride)
		}
		message.Notef("Linting package %q at %s", findings[0].PackageNameOverride, packagePathFromUser)
		message.Table(header, lintData)
	}
}

// GroupFindingsByPath groups findings by their package path
func GroupFindingsByPath(findings []PackageFinding, severity Severity, packageName string) map[string][]PackageFinding {
	findings = helpers.RemoveMatches(findings, func(finding PackageFinding) bool {
		return finding.Severity > severity
	})
	for i := range findings {
		if findings[i].PackageNameOverride == "" {
			findings[i].PackageNameOverride = packageName
		}
		if findings[i].PackagePathOverride == "" {
			findings[i].PackagePathOverride = "."
		}
	}

	mapOfFindingsByPath := make(map[string][]PackageFinding)
	for _, finding := range findings {
		mapOfFindingsByPath[finding.PackagePathOverride] = append(mapOfFindingsByPath[finding.PackagePathOverride], finding)
	}
	return mapOfFindingsByPath
}

// HasSeverity returns true if the findings contain a severity equal to or greater than the given severity
func HasSeverity(findings []PackageFinding, severity Severity) bool {
	for _, finding := range findings {
		if finding.Severity <= severity {
			return true
		}
	}
	return false
}
