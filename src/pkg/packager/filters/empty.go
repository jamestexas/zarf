// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package filters contains core implementations of the ComponentFilterStrategy interface.
package filters

import "github.com/defenseunicorns/zarf/src/types"

var (
	_ ComponentFilterStrategy = &EmptyFilter{}
)

// EmptyFilter is a filter that does nothing.
type EmptyFilter struct{}

// Apply returns the components unchanged.
func (f *EmptyFilter) Apply(components []types.ZarfComponent) ([]types.ZarfComponent, error) {
	return components, nil
}