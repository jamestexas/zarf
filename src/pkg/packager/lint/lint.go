// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package lint contains functions for verifying zarf yaml files are valid
package lint

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/defenseunicorns/zarf/src/config"
	"github.com/defenseunicorns/zarf/src/config/lang"
	"github.com/defenseunicorns/zarf/src/pkg/layout"
	"github.com/defenseunicorns/zarf/src/pkg/message"
	"github.com/defenseunicorns/zarf/src/pkg/packager/composer"
	"github.com/defenseunicorns/zarf/src/pkg/utils"
	"github.com/defenseunicorns/zarf/src/types"
)

// Validate lints the given Zarf package
func Validate(ctx context.Context, createOpts types.ZarfCreateOptions) error {
	var findings []PackageFinding
	if err := os.Chdir(createOpts.BaseDir); err != nil {
		return fmt.Errorf("unable to access directory %q: %w", createOpts.BaseDir, err)
	}

	var pkg types.ZarfPackage
	if err := utils.ReadYaml(layout.ZarfYAML, &pkg); err != nil {
		return err
	}

	compFindings, err := lintComponents(ctx, pkg, createOpts)
	if err != nil {
		return err
	}
	findings = append(findings, compFindings...)

	schemaFindings, err := ValidateSchema()
	if err != nil {
		return err
	}
	findings = append(findings, schemaFindings...)

	if len(findings) == 0 {
		message.Successf("0 findings for %q", pkg.Metadata.Name)
		return nil
	}

	PrintFindings(findings, SevWarn, createOpts.BaseDir, pkg.Metadata.Name)

	if HasSeverity(findings, SevErr) {
		return errors.New("errors during lint")
	}

	return nil
}

func lintComponents(ctx context.Context, pkg types.ZarfPackage, createOpts types.ZarfCreateOptions) ([]PackageFinding, error) {
	var findings []PackageFinding

	for i, component := range pkg.Components {
		arch := config.GetArch(pkg.Metadata.Architecture)
		if !composer.CompatibleComponent(component, arch, createOpts.Flavor) {
			continue
		}

		chain, err := composer.NewImportChain(ctx, component, i, pkg.Metadata.Name, arch, createOpts.Flavor)

		if err != nil {
			return nil, err
		}

		node := chain.Head()
		for node != nil {
			component := node.ZarfComponent
			compFindings, err := fillComponentTemplate(&component, &createOpts)
			if err != nil {
				return nil, err
			}
			compFindings = append(compFindings, CheckComponentValues(component, node.Index())...)
			for i := range compFindings {
				compFindings[i].PackagePathOverride = node.ImportLocation()
				compFindings[i].PackageNameOverride = node.OriginalPackageName()
			}
			findings = append(findings, compFindings...)
			node = node.Next()
		}
	}
	return findings, nil
}

func fillComponentTemplate(c *types.ZarfComponent, createOpts *types.ZarfCreateOptions) ([]PackageFinding, error) {
	var findings []PackageFinding
	var templateMap map[string]string

	setVarsAndWarn := func(templatePrefix string, deprecated bool) {
		yamlTemplates, err := utils.FindYamlTemplates(c, templatePrefix, "###")
		if err != nil {
			findings = append(findings, PackageFinding{
				Description: err.Error(),
				Severity:    SevWarn,
			})
		}

		for key := range yamlTemplates {
			if deprecated {
				findings = append(findings, PackageFinding{
					Description: fmt.Sprintf(lang.PkgValidateTemplateDeprecation, key, key, key),
					Severity:    SevWarn,
				})
			}
			_, present := createOpts.SetVariables[key]
			if !present {
				findings = append(findings, PackageFinding{
					Description: lang.UnsetVarLintWarning,
					Severity:    SevWarn,
				})
			}
		}

	}

	setVarsAndWarn(types.ZarfPackageTemplatePrefix, false)

	// [DEPRECATION] Set the Package Variable syntax as well for backward compatibility
	setVarsAndWarn(types.ZarfPackageVariablePrefix, true)

	if err := utils.ReloadYamlTemplate(c, templateMap); err != nil {
		return nil, err
	}
	return findings, nil
}
