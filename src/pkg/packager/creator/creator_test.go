// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package creator contains functions for creating Zarf packages.
package creator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/zarf/src/pkg/layout"
	"github.com/defenseunicorns/zarf/src/pkg/packager/lint"
	"github.com/defenseunicorns/zarf/src/types"
	"github.com/stretchr/testify/require"
)

type mockSchemaLoader struct {
	b []byte
}

func (m *mockSchemaLoader) ReadFile(_ string) ([]byte, error) {
	return m.b, nil
}

func TestLoadPackageDefinitionWithValidate(t *testing.T) {
	// TODO once creator is refactored to not expect to be in the same directory as the zarf.yaml file
	// this test can be re-parallelized
	tests := []struct {
		name        string
		testDir     string
		expectedErr string
		creator     Creator
	}{
		{
			name:        "valid package definition",
			testDir:     "valid",
			expectedErr: "",
			creator:     NewPackageCreator(types.ZarfCreateOptions{}, ""),
		},
		{
			name:        "invalid package definition",
			testDir:     "invalid",
			expectedErr: "found errors in package",
			creator:     NewPackageCreator(types.ZarfCreateOptions{}, ""),
		},
		{
			name:        "invalid package definition but no validate schema",
			testDir:     "invalid",
			expectedErr: "",
			creator:     NewPackageCreator(types.ZarfCreateOptions{}, ""),
		},
		{
			name:        "valid package definition",
			testDir:     "valid",
			expectedErr: "",
			creator:     NewSkeletonCreator(types.ZarfCreateOptions{}, types.ZarfPublishOptions{}),
		},
		{
			name:        "invalid package definition",
			testDir:     "invalid",
			expectedErr: "found errors in package",
			creator:     NewSkeletonCreator(types.ZarfCreateOptions{}, types.ZarfPublishOptions{}),
		},
	}
	b, err := os.ReadFile("../../../../zarf.schema.json")
	require.NoError(t, err)
	lint.ZarfSchema = &mockSchemaLoader{b: b}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cwd, err := os.Getwd()
			require.NoError(t, err)
			defer func() {
				err = os.Chdir(cwd)
				require.NoError(t, err)
			}()
			path := filepath.Join("testdata", tt.testDir)
			err = os.Chdir(path)
			require.NoError(t, err)

			src := layout.New(".")
			pkg, _, err := tt.creator.LoadPackageDefinitionWithValidate(context.Background(), src)

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
