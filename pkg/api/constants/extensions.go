package constants

// https://github.com/opencontainers/distribution-spec/tree/main/extensions#extensions-api-for-distribution
const (
	ExtCatalogPrefix     = "/_catalog"
	ExtOciDiscoverPrefix = "/_oci/ext/discover"
	// zot specific extensions.
	ExtSearchPrefix            = "/_zot/ext/search"
	V2ExtSearchPrefix          = RoutePrefix + ExtSearchPrefix
	ExtGQLPlaygroundEndpoint   = "/_zot/ext/graphql-playground"
	V2ExtGQLPlaygroundEndpoint = RoutePrefix + ExtGQLPlaygroundEndpoint
)
