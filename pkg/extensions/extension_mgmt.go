//go:build mgmt
// +build mgmt

package extensions

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/opencontainers/go-digest"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/signatures"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/scheduler"
)

const (
	ConfigResource     = "config"
	SignaturesResource = "signatures"
)

type HTPasswd struct {
	Path string `json:"path,omitempty"`
}

type BearerConfig struct {
	Realm   string `json:"realm,omitempty"`
	Service string `json:"service,omitempty"`
}

type OpenIDProviderConfig struct{}

type OpenIDConfig struct {
	Providers map[string]OpenIDProviderConfig `json:"providers,omitempty" mapstructure:"providers"`
}

type Auth struct {
	HTPasswd *HTPasswd     `json:"htpasswd,omitempty" mapstructure:"htpasswd"`
	Bearer   *BearerConfig `json:"bearer,omitempty" mapstructure:"bearer"`
	LDAP     *struct {
		Address string `json:"address,omitempty" mapstructure:"address"`
	} `json:"ldap,omitempty" mapstructure:"ldap"`
	OpenID *OpenIDConfig `json:"openid,omitempty" mapstructure:"openid"`
}

type StrippedConfig struct {
	DistSpecVersion string `json:"distSpecVersion" mapstructure:"distSpecVersion"`
	BinaryType      string `json:"binaryType" mapstructure:"binaryType"`
	HTTP            struct {
		Auth *Auth `json:"auth,omitempty" mapstructure:"auth"`
	} `json:"http" mapstructure:"http"`
}

func IsBuiltWithMGMTExtension() bool {
	return true
}

func (auth Auth) MarshalJSON() ([]byte, error) {
	type localAuth Auth

	if auth.Bearer == nil && auth.LDAP == nil &&
		auth.HTPasswd.Path == "" &&
		(auth.OpenID == nil || len(auth.OpenID.Providers) == 0) {
		auth.HTPasswd = nil
		auth.OpenID = nil

		return json.Marshal((localAuth)(auth))
	}

	if auth.HTPasswd.Path == "" && auth.LDAP == nil {
		auth.HTPasswd = nil
	} else {
		auth.HTPasswd.Path = ""
	}

	if auth.OpenID != nil && len(auth.OpenID.Providers) == 0 {
		auth.OpenID = nil
	}

	auth.LDAP = nil

	return json.Marshal((localAuth)(auth))
}

func SetupMgmtRoutes(conf *config.Config, router *mux.Router, log log.Logger) {
	if conf.Extensions.Mgmt == nil || !*conf.Extensions.Mgmt.Enable {
		return
	}

	log.Info().Msg("setting up mgmt routes")

	mgmt := Mgmt{Conf: conf, Log: log}

	// The endpoint for reading configuration should be available to all users
	mgmtRouter := router.PathPrefix(constants.MgmtPrefix).Subrouter()
	mgmtRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
	mgmtRouter.Use(zcommon.AddExtensionSecurityHeaders())

	allowedMethods := zcommon.AllowedMethods(http.MethodGet)

	authInfoRouter := mgmtRouter.PathPrefix(constants.AuthInfo).Subrouter()
	authInfoRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
	authInfoRouter.Methods(allowedMethods...).HandlerFunc(mgmt.HandleGetConfig)

	allowedMethods = zcommon.AllowedMethods(http.MethodPost)

	// The endpoints for uploading signatures should be available only to admins
	notationRouter := mgmtRouter.PathPrefix(constants.Notation).Subrouter()
	notationRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
	notationRouter.Use(zcommon.AuthzOnlyAdminsMiddleware(conf))
	notationRouter.Methods(allowedMethods...).HandlerFunc(mgmt.HandleNotationCertificateUpload)

	cosignRouter := mgmtRouter.PathPrefix(constants.Cosign).Subrouter()
	cosignRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
	cosignRouter.Use(zcommon.AuthzOnlyAdminsMiddleware(conf))
	cosignRouter.Methods(allowedMethods...).HandlerFunc(mgmt.HandleCosignPublicKeyUpload)
}

type Mgmt struct {
	Conf *config.Config
	Log  log.Logger
}

// Auth info handler godoc
// @Summary Get current server configuration
// @Description Get current server configuration
// @Router  /v2/_zot/mgmt/auth [get]
// @Accept  json
// @Produce json
// @Param   resource       query     string   false   "specify resource" Enums(config)
// @Success 200 {object}   extensions.StrippedConfig
// @Failure 500 {string}   string   "internal server error".
func (mgmt *Mgmt) HandleGetConfig(w http.ResponseWriter, r *http.Request) {
	sanitizedConfig := mgmt.Conf.Sanitize()

	buf, err := zcommon.MarshalThroughStruct(sanitizedConfig, &StrippedConfig{})
	if err != nil {
		mgmt.Log.Error().Err(err).Msg("mgmt: couldn't marshal config response")
		w.WriteHeader(http.StatusInternalServerError)
	}

	_, _ = w.Write(buf)
}

// Cosign handler godoc
// @Summary Upload cosign public keys for verifying signatures
// @Description Upload cosign public keys for verifying signatures
// @Router   /v2/_zot/mgmt/cosign [post]
// @Accept  octet-stream
// @Produce json
// @Param   requestBody     body     string   true   "Public key content"
// @Success 200 {string}   string    "ok"
// @Failure 400 {string}   string    "bad request".
// @Failure 500 {string}   string    "internal server error".
func (mgmt *Mgmt) HandleCosignPublicKeyUpload(response http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		mgmt.Log.Error().Err(err).Msg("mgmt: couldn't read cosign key body")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	err = signatures.UploadPublicKey(body)
	if err != nil {
		if errors.Is(err, zerr.ErrInvalidPublicKeyContent) {
			response.WriteHeader(http.StatusBadRequest)
		} else {
			mgmt.Log.Error().Err(err).Msg("mgmt: failed to save cosign key")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.WriteHeader(http.StatusOK)
}

// Notation handler godoc
// @Summary Upload notation certificates for verifying signatures
// @Description Upload notation certificates for verifying signatures
// @Router  /v2/_zot/mgmt/notation [post]
// @Accept  octet-stream
// @Produce json
// @Param   truststoreType  query    string   false  "truststore type"
// @Param   truststoreName  query    string   false  "truststore name"
// @Param   requestBody     body     string   true   "Certificate content"
// @Success 200 {string}   string    "ok"
// @Failure 400 {string}   string    "bad request".
// @Failure 500 {string}   string    "internal server error".
func (mgmt *Mgmt) HandleNotationCertificateUpload(response http.ResponseWriter, request *http.Request) {
	var truststoreType string

	if !zcommon.QueryHasParams(request.URL.Query(), []string{"truststoreName"}) {
		response.WriteHeader(http.StatusBadRequest)

		return
	}

	if zcommon.QueryHasParams(request.URL.Query(), []string{"truststoreType"}) {
		truststoreType = request.URL.Query().Get("truststoreType")
	} else {
		truststoreType = "ca" // default value of "truststoreType" query param
	}

	truststoreName := request.URL.Query().Get("truststoreName")

	if truststoreType == "" || truststoreName == "" {
		response.WriteHeader(http.StatusBadRequest)

		return
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		mgmt.Log.Error().Err(err).Msg("mgmt: couldn't read notation certificate body")
		response.WriteHeader(http.StatusInternalServerError)

		return
	}

	err = signatures.UploadCertificate(body, truststoreType, truststoreName)
	if err != nil {
		if errors.Is(err, zerr.ErrInvalidTruststoreType) ||
			errors.Is(err, zerr.ErrInvalidTruststoreName) ||
			errors.Is(err, zerr.ErrInvalidCertificateContent) {
			response.WriteHeader(http.StatusBadRequest)
		} else {
			mgmt.Log.Error().Err(err).Msg("mgmt: failed to save notation certificate")
			response.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	response.WriteHeader(http.StatusOK)
}

func EnablePeriodicSignaturesVerification(config *config.Config, taskScheduler *scheduler.Scheduler,
	metaDB mTypes.MetaDB, log log.Logger,
) {
	if config.Extensions.Search != nil && *config.Extensions.Search.Enable {
		ctx := context.Background()

		repos, err := metaDB.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMetadata) bool {
			return true
		}, mTypes.PageInput{})
		if err != nil {
			return
		}

		generator := &taskGeneratorSigValidity{
			repos:     repos,
			metaDB:    metaDB,
			repoIndex: -1,
			log:       log,
		}

		numberOfHours := 2
		interval := time.Duration(numberOfHours) * time.Minute
		taskScheduler.SubmitGenerator(generator, interval, scheduler.MediumPriority)
	}
}

type taskGeneratorSigValidity struct {
	repos     []mTypes.RepoMetadata
	metaDB    mTypes.MetaDB
	repoIndex int
	done      bool
	log       log.Logger
}

func (gen *taskGeneratorSigValidity) Next() (scheduler.Task, error) {
	gen.repoIndex++

	if gen.repoIndex >= len(gen.repos) {
		gen.done = true

		return nil, nil
	}

	return NewValidityTask(gen.metaDB, gen.repos[gen.repoIndex], gen.log), nil
}

func (gen *taskGeneratorSigValidity) IsDone() bool {
	return gen.done
}

func (gen *taskGeneratorSigValidity) Reset() {
	gen.done = false
	gen.repoIndex = -1
	ctx := context.Background()

	repos, err := gen.metaDB.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMetadata) bool {
		return true
	}, mTypes.PageInput{})
	if err != nil {
		return
	}

	gen.repos = repos
}

type validityTask struct {
	metaDB mTypes.MetaDB
	repo   mTypes.RepoMetadata
	log    log.Logger
}

func NewValidityTask(metaDB mTypes.MetaDB, repo mTypes.RepoMetadata, log log.Logger) *validityTask {
	return &validityTask{metaDB, repo, log}
}

func (validityT *validityTask) DoWork() error {
	validityT.log.Info().Msg("updating signatures validity")

	for signedManifest, sigs := range validityT.repo.Signatures {
		if len(sigs[signatures.CosignSignature]) != 0 || len(sigs[signatures.NotationSignature]) != 0 {
			err := validityT.metaDB.UpdateSignaturesValidity(validityT.repo.Name, digest.Digest(signedManifest))
			if err != nil {
				validityT.log.Info().Msg("error while verifying signatures")

				return err
			}
		}
	}

	validityT.log.Info().Msg("verifying signatures successfully completed")

	return nil
}
