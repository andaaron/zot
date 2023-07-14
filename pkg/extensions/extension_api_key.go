//go:build userprefs
// +build userprefs

package extensions

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	guuid "github.com/gofrs/uuid"
	"github.com/gorilla/sessions"
	jsoniter "github.com/json-iterator/go"
	godigest "github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
)

func AreAPIKeysEnabled(config *config.Config) bool {
	return config.Extensions.APIKey != nil && *config.Extensions.APIKey.Enable
}

type APIKeyPayload struct { //nolint:revive
	Label  string   `json:"label"`
	Scopes []string `json:"scopes"`
}

func HandleAPIKeyRequest(metaDB mTypes.MetaDB, cookieStore sessions.Store,
	log log.Logger,
) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodPost:
			CreateAPIKey(resp, req, metaDB, cookieStore, log) //nolint:contextcheck

			return
		case http.MethodDelete:
			RevokeAPIKey(resp, req, metaDB, cookieStore, log) //nolint:contextcheck

			return
		}
	})
}

// CreateAPIKey godoc
// @Summary Create an API key for the current user
// @Description Can create an api key for a logged in user, based on the provided label and scopes.
// @Accept  json
// @Produce json
// @Success 201 {string} string "created"
// @Failure 401 {string} string "unauthorized"
// @Failure 500 {string} string "internal server error"
// @Router /v2/_zot/userprefs/apikey  [post].
func CreateAPIKey(resp http.ResponseWriter, req *http.Request, metaDB mTypes.MetaDB,
	cookieStore sessions.Store, log log.Logger,
) {
	var payload APIKeyPayload

	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Error().Msg("unable to read request body")
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	err = json.Unmarshal(body, &payload)
	if err != nil {
		log.Error().Err(err).Msg("unable to unmarshal body")
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	apiKeyBase, err := guuid.NewV4()
	if err != nil {
		log.Error().Err(err).Msg("unable to generate uuid")
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	apiKey := strings.ReplaceAll(apiKeyBase.String(), "-", "")

	hashedAPIKey := hashUUID(apiKey)

	// will be used for identifying a specific api key
	apiKeyID, err := guuid.NewV4()
	if err != nil {
		log.Error().Err(err).Msg("unable to generate uuid")
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	apiKeyDetails := &mTypes.APIKeyDetails{
		CreatedAt:   time.Now(),
		LastUsed:    time.Now(),
		CreatorUA:   req.UserAgent(),
		GeneratedBy: "manual",
		Label:       payload.Label,
		Scopes:      payload.Scopes,
		UUID:        apiKeyID.String(),
	}

	err = metaDB.AddUserAPIKey(req.Context(), hashedAPIKey, apiKeyDetails)
	if err != nil {
		log.Error().Err(err).Msg("error storing API key")
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	apiKeyResponse := struct {
		mTypes.APIKeyDetails
		APIKey string `json:"apiKey"`
	}{
		APIKey:        fmt.Sprintf("%s%s", constants.APIKeysPrefix, apiKey),
		APIKeyDetails: *apiKeyDetails,
	}

	json := jsoniter.ConfigCompatibleWithStandardLibrary

	data, err := json.Marshal(apiKeyResponse)
	if err != nil {
		log.Error().Err(err).Msg("unable to marshal api key response")

		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	resp.Header().Set("Content-Type", constants.DefaultMediaType)
	resp.WriteHeader(http.StatusCreated)
	_, _ = resp.Write(data)
}

// RevokeAPIKey godoc
// @Summary Revokes one current user API key
// @Description Revokes one current user API key based on given key ID
// @Accept  json
// @Produce json
// @Param   id     	path    string     true        "api token id (UUID)"
// @Success 200 {string} string "ok"
// @Failure 500 {string} string "internal server error"
// @Failure 401 {string} string "unauthorized"
// @Failure 400 {string} string "bad request"
// @Router /v2/_zot/userprefs/apikey?id=UUID [delete].
func RevokeAPIKey(resp http.ResponseWriter, req *http.Request, metaDB mTypes.MetaDB,
	cookieStore sessions.Store, log log.Logger,
) {
	ids, ok := req.URL.Query()["id"]
	if !ok || len(ids) != 1 {
		resp.WriteHeader(http.StatusBadRequest)

		return
	}

	keyID := ids[0]

	err := metaDB.DeleteUserAPIKey(req.Context(), keyID)
	if err != nil {
		log.Error().Err(err).Str("keyID", keyID).Msg("error deleting API key")
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	resp.WriteHeader(http.StatusOK)
}

func hashUUID(uuid string) string {
	digester := sha256.New()
	digester.Write([]byte(uuid))

	return godigest.NewDigestFromEncoded(godigest.SHA256, fmt.Sprintf("%x", digester.Sum(nil))).Encoded()
}
