// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package rules verifies that Zarf packages are following best practices.
package rules

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGroupFindingsByPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		findings    []PackageFinding
		severity    Severity
		packageName string
		want        map[string][]PackageFinding
	}{
		{
			name: "same package multiple findings",
			findings: []PackageFinding{
				{Severity: SevWarn, PackageNameOverride: "import", PackagePathOverride: "path"},
				{Severity: SevWarn, PackageNameOverride: "import", PackagePathOverride: "path"},
			},
			severity:    SevWarn,
			packageName: "testPackage",
			want: map[string][]PackageFinding{
				"path": {
					{Severity: SevWarn, PackageNameOverride: "import", PackagePathOverride: "path"},
					{Severity: SevWarn, PackageNameOverride: "import", PackagePathOverride: "path"},
				},
			},
		},
		{
			name: "different packages single finding",
			findings: []PackageFinding{
				{Severity: SevWarn, PackageNameOverride: "import", PackagePathOverride: "path"},
				{Severity: SevErr, PackageNameOverride: "", PackagePathOverride: ""},
			},
			severity:    SevWarn,
			packageName: "testPackage",
			want: map[string][]PackageFinding{
				"path": {{Severity: SevWarn, PackageNameOverride: "import", PackagePathOverride: "path"}},
				".":    {{Severity: SevErr, PackageNameOverride: "testPackage", PackagePathOverride: "."}},
			},
		},
		{
			name: "Multiple findings, mixed severity",
			findings: []PackageFinding{
				{Severity: SevWarn, PackageNameOverride: "", PackagePathOverride: ""},
				{Severity: SevErr, PackageNameOverride: "", PackagePathOverride: ""},
			},
			severity:    SevErr,
			packageName: "testPackage",
			want: map[string][]PackageFinding{
				".": {{Severity: SevErr, PackageNameOverride: "testPackage", PackagePathOverride: "."}},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, GroupFindingsByPath(tt.findings, tt.severity, tt.packageName))
		})
	}
}

func TestHasSeverity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		severity Severity
		expected bool
		findings []PackageFinding
	}{
		{
			name: "error severity present",
			findings: []PackageFinding{
				{
					Severity: SevErr,
				},
			},
			severity: SevErr,
			expected: true,
		},
		{
			name: "error severity not present",
			findings: []PackageFinding{
				{
					Severity: SevWarn,
				},
			},
			severity: SevErr,
			expected: false,
		},
		{
			name: "err and warning severity present",
			findings: []PackageFinding{
				{
					Severity: SevWarn,
				},
				{
					Severity: SevErr,
				},
			},
			severity: SevErr,
			expected: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expected, HasSeverity(tt.findings, tt.severity))
		})
	}
}
