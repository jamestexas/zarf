// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package creator contains functions for creating Zarf packages.
package creator

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/zarf/src/pkg/layout"
	"github.com/defenseunicorns/zarf/src/pkg/packager/lint"
	"github.com/defenseunicorns/zarf/src/types"
	"github.com/stretchr/testify/require"
)

func TestSkeletonLoadPackageDefinition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		testDir     string
		expectedErr string
	}{
		{
			name:        "valid package definition",
			testDir:     "valid",
			expectedErr: "",
		},
		{
			name:        "invalid package definition",
			testDir:     "invalid",
			expectedErr: "errors during lint",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lint.ZarfSchema = &mockSchemaLoader{}

			src := layout.New(filepath.Join("testdata", tt.testDir))
			sc := NewSkeletonCreator(types.ZarfCreateOptions{}, types.ZarfPublishOptions{})
			pkg, _, err := sc.LoadPackageDefinition(context.Background(), src)

			if tt.expectedErr == "" {
				require.NoError(t, err)
				require.NotEmpty(t, pkg)
				return
			}

			require.EqualError(t, err, tt.expectedErr)
			require.Empty(t, pkg)
		})
	}
}
