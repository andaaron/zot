package constants

// https://github.com/opencontainers/distribution-spec/tree/main/extensions#extensions-api-for-distribution
const (
	ExtCatalogPrefix     = "/_catalog"
	ExtOciDiscoverPrefix = "/_oci/ext/discover"

	// zot specific extensions.
	BasePrefix = "/_zot"
	ExtPrefix  = BasePrefix + "/ext"

	// search extension.
	ExtSearch        = "/search"
	ExtSearchPrefix  = ExtPrefix + ExtSearch
	FullSearchPrefix = RoutePrefix + ExtSearchPrefix

	// mgmt extension.
	Mgmt             = "/mgmt"
	MgmtPrefix       = BasePrefix + Mgmt
	FullMgmtPrefix   = RoutePrefix + MgmtPrefix
	AuthInfo         = "/auth"
	MgmtAuth         = MgmtPrefix + AuthInfo
	FullMgmtAuth     = RoutePrefix + MgmtAuth
	Notation         = "/notation"
	MgmtNotation     = MgmtPrefix + Notation
	FullMgmtNotation = RoutePrefix + MgmtNotation
	Cosign           = "/cosign"
	MgmtCosign       = MgmtPrefix + Cosign
	FullMgmtCosign   = RoutePrefix + MgmtCosign

	// user preferences extension.
	UserPrefs           = "/userprefs"
	UserPrefsPrefix     = BasePrefix + UserPrefs
	FullUserPrefsPrefix = RoutePrefix + UserPrefsPrefix
	RepoPrefs           = "/repo"
	UserPrefsRepo       = UserPrefsPrefix + RepoPrefs
	FullUserPrefsRepo   = RoutePrefix + UserPrefsRepo
	APIKeyPrefs         = "/apikey"
	UserPrefsAPIKey     = UserPrefsPrefix + APIKeyPrefs
	FullUserPrefsAPIKey = RoutePrefix + UserPrefsAPIKey
)
