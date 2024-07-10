// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package rules verifies that Zarf packages are following best practices.
package rules

import (
	"fmt"
	"strings"

	"github.com/defenseunicorns/pkg/helpers/v2"
	"github.com/defenseunicorns/zarf/src/pkg/transform"
	"github.com/defenseunicorns/zarf/src/types"
)

func isPinnedImage(image string) (bool, error) {
	transformedImage, err := transform.ParseImageRef(image)
	if err != nil {
		if strings.Contains(image, types.ZarfPackageTemplatePrefix) ||
			strings.Contains(image, types.ZarfPackageVariablePrefix) {
			return true, nil
		}
		return false, err
	}
	return (transformedImage.Digest != ""), err
}

func isPinnedRepo(repo string) bool {
	return (strings.Contains(repo, "@"))
}

// CheckComponentValues runs lint rules validating values on component keys, should be run after templating
func CheckComponentValues(c types.ZarfComponent, i int) []PackageFinding {
	var findings []PackageFinding
	findings = append(findings, checkForUnpinnedRepos(c, i)...)
	findings = append(findings, checkForUnpinnedImages(c, i)...)
	findings = append(findings, checkForUnpinnedFiles(c, i)...)
	return findings
}

// CheckComponentKeys runs lint rules validating keys on components, can be run before templating
func CheckComponentKeys(c types.ZarfComponent, i int) []PackageFinding {
	var findings []PackageFinding
	finding, hasGroup := checkForGroup(c, i)
	if hasGroup {
		findings = append(findings, finding)
	}
	finding, hasCosign := checkForCosignKeyPath(c, i)
	if hasCosign {
		findings = append(findings, finding)
	}
	return findings
}

func checkForGroup(c types.ZarfComponent, i int) (PackageFinding, bool) {
	if c.DeprecatedGroup != "" {
		return PackageFinding{
			YqPath:      fmt.Sprintf(".components.[%d].group", i),
			Description: fmt.Sprintf("Component %s is using group which has been deprecated and will be removed in v1.0.0", c.Name),
			Severity:    SevWarn,
		}, true
	}
	return PackageFinding{}, false
}

func checkForCosignKeyPath(c types.ZarfComponent, i int) (PackageFinding, bool) {
	if c.DeprecatedCosignKeyPath != "" {
		return PackageFinding{
			YqPath:      fmt.Sprintf(".components.[%d].cosignKeyPath", i),
			Description: fmt.Sprintf("Component %s is using cosignKeyPath which has been deprecated and will be removed in v1.0.0", c.Name),
			Severity:    SevWarn,
		}, true
	}
	return PackageFinding{}, false
}

func checkForUnpinnedRepos(c types.ZarfComponent, i int) []PackageFinding {
	var findings []PackageFinding
	for j, repo := range c.Repos {
		repoYqPath := fmt.Sprintf(".components.[%d].repos.[%d]", i, j)
		if !isPinnedRepo(repo) {
			findings = append(findings, PackageFinding{
				YqPath:      repoYqPath,
				Description: "Unpinned repository",
				Item:        repo,
				Severity:    SevWarn,
			})
		}
	}
	return findings
}

func checkForUnpinnedImages(c types.ZarfComponent, i int) []PackageFinding {
	var findings []PackageFinding
	for j, image := range c.Images {
		imageYqPath := fmt.Sprintf(".components.[%d].images.[%d]", i, j)
		pinnedImage, err := isPinnedImage(image)
		if err != nil {
			findings = append(findings, PackageFinding{
				YqPath:      imageYqPath,
				Description: "Failed to parse image reference",
				Item:        image,
				Severity:    SevWarn,
			})
			continue
		}
		if !pinnedImage {
			findings = append(findings, PackageFinding{
				YqPath:      imageYqPath,
				Description: "Image not pinned with digest",
				Item:        image,
				Severity:    SevWarn,
			})
		}
	}
	return findings
}

func checkForUnpinnedFiles(c types.ZarfComponent, i int) []PackageFinding {
	var findings []PackageFinding
	for j, file := range c.Files {
		fileYqPath := fmt.Sprintf(".components.[%d].files.[%d]", i, j)
		if file.Shasum == "" && helpers.IsURL(file.Source) {
			findings = append(findings, PackageFinding{
				YqPath:      fileYqPath,
				Description: "No shasum for remote file",
				Item:        file.Source,
				Severity:    SevWarn,
			})
		}
	}
	return findings
}
