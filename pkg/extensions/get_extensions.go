package extensions

import (
	distext "github.com/opencontainers/distribution-spec/specs-go/v1/extensions"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
)

func GetExtensions(config *config.Config) distext.ExtensionList {
	extensionList := distext.ExtensionList{}

	endpoints := []string{}
	extensions := []distext.Extension{}

	if config.Extensions != nil {
		if config.Extensions.Search != nil {
			if IsBuiltWithSearchExtension() {
				endpoints = append(endpoints, constants.FullSearchPrefix)
			}

			if IsBuiltWithUserPrefsExtension() {
				endpoints = append(endpoints, constants.FullUserPrefsRepo)
			}
		}

		if config.Extensions.APIKey != nil && IsBuiltWithUserPrefsExtension() {
			endpoints = append(endpoints, constants.FullUserPrefsAPIKey)
		}

		if config.Extensions.Mgmt != nil && IsBuiltWithMGMTExtension() {
			endpoints = append(endpoints, constants.FullMgmtAuth)
			endpoints = append(endpoints, constants.FullMgmtNotation)
			endpoints = append(endpoints, constants.FullMgmtCosign)
		}
	}

	if len(endpoints) > 0 {
		extensions = append(extensions, distext.Extension{
			Name:        "_zot",
			URL:         "https://github.com/project-zot/zot/blob/" + config.ReleaseTag + "/pkg/extensions/_zot.md",
			Description: "zot registry extensions",
			Endpoints:   endpoints,
		})
	}

	extensionList.Extensions = extensions

	return extensionList
}
