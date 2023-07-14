//go:build sync || metrics || mgmt || userprefs || search
// +build sync metrics mgmt userprefs search

package extensions_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	syncconf "zotregistry.io/zot/pkg/extensions/config/sync"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
)

const (
	ServerCert = "../../test/data/server.cert"
	ServerKey  = "../../test/data/server.key"
)

func TestEnableExtension(t *testing.T) {
	Convey("Verify log if sync disabled in config", t, func() {
		globalDir := t.TempDir()
		port := test.GetFreePort()
		conf := config.New()
		falseValue := false

		syncConfig := &syncconf.Config{
			Enable:     &falseValue,
			Registries: []syncconf.RegistryConfig{},
		}

		// conf.Extensions.Sync.Enable = &falseValue
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Sync = syncConfig
		conf.HTTP.Port = port

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Level = "info"
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		defer ctlrManager.StopServer()

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager.StartAndWait(port)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			"Sync registries config not provided or disabled, skipping sync")
	})
}

func TestMetricsExtension(t *testing.T) {
	Convey("Verify Metrics enabled for storage subpaths", t, func() {
		globalDir := t.TempDir()
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		defaultValue := true

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Metrics = &extconf.MetricsConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultValue},
			Prometheus: &extconf.PrometheusConfig{},
		}
		conf.Log.Level = "info"
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{
			Dedupe:        false,
			RootDirectory: t.TempDir(),
		}

		ctlr.Config.Storage.RootDirectory = globalDir
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager.StartAndWait(port)

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring,
			"Prometheus instrumentation Path not set, changing to '/metrics'.")
	})
}

func TestMgmtExtension(t *testing.T) {
	globalDir := t.TempDir()
	conf := config.New()
	port := test.GetFreePort()
	conf.HTTP.Port = port
	baseURL := test.GetBaseURL(port)

	logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	defaultValue := true

	mockOIDCServer, err := test.MockOIDCRun()
	if err != nil {
		panic(err)
	}

	defer func() {
		err := mockOIDCServer.Shutdown()
		if err != nil {
			panic(err)
		}
	}()

	mockOIDCConfig := mockOIDCServer.Config()

	Convey("Verify mgmt auth info route enabled with htpasswd", t, func() {
		htpasswdPath := test.MakeHtpasswdFile()
		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{RootDirectory: t.TempDir()}

		ctlr.Config.Storage.RootDirectory = globalDir
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring, "setting up mgmt routes")

		Convey("unsupported http method call", func() {
			// without credentials
			resp, err := resty.R().Patch(baseURL + constants.FullMgmtAuth)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)
		})

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)

		// with credentials
		resp, err = resty.R().SetBasicAuth("test", "test").Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp = extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)

		// with wrong credentials
		resp, err = resty.R().SetBasicAuth("test", "wrong").Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})

	Convey("Verify mgmt auth info route enabled with ldap", t, func() {
		conf.HTTP.Auth.LDAP = &config.LDAPConfig{
			BindDN:  "binddn",
			BaseDN:  "basedn",
			Address: "ldapexample",
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{RootDirectory: t.TempDir()}

		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring, "setting up mgmt routes")

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		// ldap is always nil, htpasswd should be populated when ldap is used
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
	})

	Convey("Verify mgmt auth info route enabled with htpasswd + ldap", t, func() {
		htpasswdPath := test.MakeHtpasswdFile()
		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath
		conf.HTTP.Auth.LDAP = &config.LDAPConfig{
			BindDN:  "binddn",
			BaseDN:  "basedn",
			Address: "ldapexample",
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{RootDirectory: t.TempDir()}

		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring, "setting up mgmt routes")

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)

		// with credentials
		resp, err = resty.R().SetBasicAuth("test", "test").Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp = extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
	})

	Convey("Verify mgmt auth info route enabled with htpasswd + ldap + bearer", t, func() {
		htpasswdPath := test.MakeHtpasswdFile()
		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath
		conf.HTTP.Auth.LDAP = &config.LDAPConfig{
			BindDN:  "binddn",
			BaseDN:  "basedn",
			Address: "ldapexample",
		}

		conf.HTTP.Auth.Bearer = &config.BearerConfig{
			Realm:   "realm",
			Service: "service",
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring, "setting up mgmt routes")

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, "realm")
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, "service")

		// with credentials
		resp, err = resty.R().SetBasicAuth("test", "test").Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp = extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, "realm")
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, "service")
	})

	Convey("Verify mgmt auth info route enabled with ldap + bearer", t, func() {
		conf.HTTP.Auth.HTPasswd.Path = ""
		conf.HTTP.Auth.LDAP = &config.LDAPConfig{
			BindDN:  "binddn",
			BaseDN:  "basedn",
			Address: "ldapexample",
		}

		conf.HTTP.Auth.Bearer = &config.BearerConfig{
			Realm:   "realm",
			Service: "service",
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{RootDirectory: t.TempDir()}

		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring, "setting up mgmt routes")

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, "realm")
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, "service")
	})

	Convey("Verify mgmt auth info route enabled with bearer", t, func() {
		conf.HTTP.Auth.HTPasswd.Path = ""
		conf.HTTP.Auth.LDAP = nil
		conf.HTTP.Auth.Bearer = &config.BearerConfig{
			Realm:   "realm",
			Service: "service",
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring, "setting up mgmt routes")

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, "realm")
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, "service")
	})

	Convey("Verify mgmt auth info route enabled with openID", t, func() {
		conf.HTTP.Auth.HTPasswd.Path = ""
		conf.HTTP.Auth.LDAP = nil
		conf.HTTP.Auth.Bearer = nil

		openIDProviders := make(map[string]config.OpenIDProviderConfig)
		openIDProviders["dex"] = config.OpenIDProviderConfig{
			ClientID:     mockOIDCConfig.ClientID,
			ClientSecret: mockOIDCConfig.ClientSecret,
			Issuer:       mockOIDCConfig.Issuer,
		}

		conf.HTTP.Auth.OpenID = &config.OpenIDConfig{
			Providers: openIDProviders,
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring, "setting up mgmt routes")

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		t.Logf("resp: %v", mgmtResp.HTTP.Auth.OpenID)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.OpenID, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.OpenID.Providers, ShouldNotBeEmpty)
	})

	Convey("Verify mgmt auth info route enabled with empty openID provider list", t, func() {
		htpasswdPath := test.MakeHtpasswdFile()

		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath
		conf.HTTP.Auth.LDAP = nil
		conf.HTTP.Auth.Bearer = nil

		openIDProviders := make(map[string]config.OpenIDProviderConfig)

		conf.HTTP.Auth.OpenID = &config.OpenIDConfig{
			Providers: openIDProviders,
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring, "setting up mgmt routes")

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		t.Logf("resp: %v", mgmtResp.HTTP.Auth.OpenID)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.OpenID, ShouldBeNil)
	})

	Convey("Verify mgmt auth info route enabled without any auth", t, func() {
		globalDir := t.TempDir()
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port
		baseURL := test.GetBaseURL(port)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		defaultValue := true

		conf.Commit = "v1.0.0"

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		resp, err := resty.R().Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.DistSpecVersion, ShouldResemble, conf.DistSpecVersion)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)

		data, _ := os.ReadFile(logFile.Name())
		So(string(data), ShouldContainSubstring, "setting up mgmt routes")
	})

	Convey("Verify mgmt routes enabled for uploading notation certificates", t, func() {
		globalDir := t.TempDir()

		conf := config.New()
		port := test.GetFreePort()
		defaultValue := true

		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		baseURL := test.GetBaseURL(port)
		repo := "repo"
		tag := "0.0.1"
		certName := "test"
		gqlEndpoint := fmt.Sprintf("%s%s?query=", baseURL, constants.FullSearchPrefix)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		defer os.Remove(logFile.Name()) // cleanup
		So(err, ShouldBeNil)

		logger := log.NewLogger("debug", logFile.Name())
		writers := io.MultiWriter(os.Stdout, logFile)
		logger.Logger = logger.Output(writers)

		imageStore := local.NewImageStore(globalDir, false, 0, false, false,
			logger, monitoring.NewMetricsServer(false, logger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		config, layers, manifest, err := test.GetRandomImageComponents(10)
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(
			test.Image{
				Manifest:  manifest,
				Layers:    layers,
				Config:    config,
				Reference: tag,
			}, repo, storeController,
		)
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBlob)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(), "setting up mgmt routes", time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		gqlQuery := `
			{
				Image(image:"%s:%s"){
					RepoName Tag Digest IsSigned
					Manifests {
						Digest
						SignatureInfo { Tool IsTrusted Author }
					}
					SignatureInfo { Tool IsTrusted Author }
				}
			}`
		strQuery := fmt.Sprintf(gqlQuery, repo, tag)
		gqlTargetURL := fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		// Verify the image is initially shown as not being signed
		resp, err := resty.R().Get(gqlTargetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		imgSummaryResponse := zcommon.ImageSummaryResult{}
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)
		imgSummary := imgSummaryResponse.SingleImageSummary.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repo)
		So(imgSummary.Tag, ShouldContainSubstring, tag)
		So(imgSummary.Digest, ShouldContainSubstring, manifestDigest.Encoded())
		So(imgSummary.Manifests[0].Digest, ShouldContainSubstring, manifestDigest.Encoded())
		So(imgSummary.IsSigned, ShouldEqual, false)
		So(imgSummary.SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.SignatureInfo), ShouldEqual, 0)
		So(imgSummary.Manifests[0].SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.Manifests[0].SignatureInfo), ShouldEqual, 0)

		rootDir := t.TempDir()

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(rootDir)

		// generate a keypair
		err = test.GenerateNotationCerts(rootDir, certName)
		So(err, ShouldBeNil)

		// upload the certificate
		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", fmt.Sprintf("%s.crt", certName)))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		client := resty.New()
		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetQueryParam("truststoreName", certName).
			SetBody(certificateContent).Post(baseURL + constants.FullMgmtNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// sign the image
		image := fmt.Sprintf("localhost:%s/%s", port, fmt.Sprintf("%s:%s", repo, tag))

		err = test.SignWithNotation(certName, image, rootDir)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "updating signatures validity", 10*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "verifying signatures successfully completed",
			time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		// verify the image is shown as signed and trusted
		resp, err = resty.R().Get(gqlTargetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		imgSummaryResponse = zcommon.ImageSummaryResult{}
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)
		imgSummary = imgSummaryResponse.SingleImageSummary.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repo)
		So(imgSummary.Tag, ShouldContainSubstring, tag)
		So(imgSummary.Digest, ShouldContainSubstring, manifestDigest.Encoded())
		So(imgSummary.Manifests[0].Digest, ShouldContainSubstring, manifestDigest.Encoded())
		t.Log(imgSummary.SignatureInfo)
		So(imgSummary.IsSigned, ShouldEqual, true)
		So(imgSummary.SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.SignatureInfo), ShouldEqual, 1)
		So(imgSummary.SignatureInfo[0].IsTrusted, ShouldEqual, true)
		So(imgSummary.SignatureInfo[0].Tool, ShouldEqual, "notation")
		So(imgSummary.SignatureInfo[0].Author,
			ShouldEqual, "CN=cert,O=Notary,L=Seattle,ST=WA,C=US")
		So(imgSummary.Manifests[0].SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.Manifests[0].SignatureInfo), ShouldEqual, 1)
		t.Log(imgSummary.Manifests[0].SignatureInfo)
		So(imgSummary.Manifests[0].SignatureInfo[0].IsTrusted, ShouldEqual, true)
		So(imgSummary.Manifests[0].SignatureInfo[0].Tool, ShouldEqual, "notation")
		So(imgSummary.Manifests[0].SignatureInfo[0].Author,
			ShouldEqual, "CN=cert,O=Notary,L=Seattle,ST=WA,C=US")

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(certificateContent).Post(baseURL + constants.FullMgmtNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetQueryParam("truststoreName", "").
			SetBody(certificateContent).Post(baseURL + constants.FullMgmtNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetQueryParam("truststoreName", "test").
			SetQueryParam("truststoreType", "signatureAuthority").
			SetBody([]byte("wrong content")).Post(baseURL + constants.FullMgmtNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().Get(baseURL + constants.FullMgmtNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)

		resp, err = client.R().Post(baseURL + constants.FullMgmtNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
	})

	Convey("Verify mgmt routes enabled for uploading cosign public keys", t, func() {
		globalDir := t.TempDir()

		conf := config.New()
		port := test.GetFreePort()
		defaultValue := true

		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		baseURL := test.GetBaseURL(port)
		repo := "repo"
		tag := "0.0.1"
		gqlEndpoint := fmt.Sprintf("%s%s?query=", baseURL, constants.FullSearchPrefix)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		defer os.Remove(logFile.Name()) // cleanup
		So(err, ShouldBeNil)

		logger := log.NewLogger("debug", logFile.Name())
		writers := io.MultiWriter(os.Stdout, logFile)
		logger.Logger = logger.Output(writers)

		imageStore := local.NewImageStore(globalDir, false, 0, false, false,
			logger, monitoring.NewMetricsServer(false, logger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		config, layers, manifest, err := test.GetRandomImageComponents(10)
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(
			test.Image{
				Manifest:  manifest,
				Layers:    layers,
				Config:    config,
				Reference: tag,
			}, repo, storeController,
		)
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBlob)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(), "setting up mgmt routes", time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		gqlQuery := `
			{
				Image(image:"%s:%s"){
					RepoName Tag Digest IsSigned
					Manifests {
						Digest
						SignatureInfo { Tool IsTrusted Author }
					}
					SignatureInfo { Tool IsTrusted Author }
				}
			}`
		strQuery := fmt.Sprintf(gqlQuery, repo, tag)
		gqlTargetURL := fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		// Verify the image is initially shown as not being signed
		resp, err := resty.R().Get(gqlTargetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		imgSummaryResponse := zcommon.ImageSummaryResult{}
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)
		imgSummary := imgSummaryResponse.SingleImageSummary.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repo)
		So(imgSummary.Tag, ShouldContainSubstring, tag)
		So(imgSummary.Digest, ShouldContainSubstring, manifestDigest.Encoded())
		So(imgSummary.Manifests[0].Digest, ShouldContainSubstring, manifestDigest.Encoded())
		So(imgSummary.IsSigned, ShouldEqual, false)
		So(imgSummary.SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.SignatureInfo), ShouldEqual, 0)
		So(imgSummary.Manifests[0].SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.Manifests[0].SignatureInfo), ShouldEqual, 0)

		// generate a keypair
		keyDir := t.TempDir()

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		_ = os.Chdir(keyDir)

		os.Setenv("COSIGN_PASSWORD", "")
		err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
		So(err, ShouldBeNil)

		_ = os.Chdir(cwd)

		publicKeyContent, err := os.ReadFile(path.Join(keyDir, "cosign.pub"))
		So(err, ShouldBeNil)
		So(publicKeyContent, ShouldNotBeNil)

		// upload the public key
		client := resty.New()
		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullMgmtCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// sign the image
		err = sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
			options.KeyOpts{KeyRef: path.Join(keyDir, "cosign.key"), PassFunc: generate.GetPass},
			options.SignOptions{
				Registry:          options.RegistryOptions{AllowInsecure: true},
				AnnotationOptions: options.AnnotationOptions{Annotations: []string{fmt.Sprintf("tag=%s", tag)}},
				Upload:            true,
			},
			[]string{fmt.Sprintf("localhost:%s/%s@%s", port, repo, manifestDigest.String())})
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "updating signatures validity", 10*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(), "verifying signatures successfully completed",
			time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		// verify the image is shown as signed and trusted
		resp, err = resty.R().Get(gqlTargetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		imgSummaryResponse = zcommon.ImageSummaryResult{}
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.ImageSummary, ShouldNotBeNil)
		imgSummary = imgSummaryResponse.SingleImageSummary.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repo)
		So(imgSummary.Tag, ShouldContainSubstring, tag)
		So(imgSummary.Digest, ShouldContainSubstring, manifestDigest.Encoded())
		So(imgSummary.Manifests[0].Digest, ShouldContainSubstring, manifestDigest.Encoded())
		t.Log(imgSummary.SignatureInfo)
		So(imgSummary.SignatureInfo, ShouldNotBeNil)
		So(imgSummary.IsSigned, ShouldEqual, true)
		So(len(imgSummary.SignatureInfo), ShouldEqual, 1)
		So(imgSummary.SignatureInfo[0].IsTrusted, ShouldEqual, true)
		So(imgSummary.SignatureInfo[0].Tool, ShouldEqual, "cosign")
		So(imgSummary.SignatureInfo[0].Author, ShouldEqual, string(publicKeyContent))
		So(imgSummary.Manifests[0].SignatureInfo, ShouldNotBeNil)
		So(len(imgSummary.Manifests[0].SignatureInfo), ShouldEqual, 1)
		t.Log(imgSummary.Manifests[0].SignatureInfo)
		So(imgSummary.Manifests[0].SignatureInfo[0].IsTrusted, ShouldEqual, true)
		So(imgSummary.Manifests[0].SignatureInfo[0].Tool, ShouldEqual, "cosign")
		So(imgSummary.Manifests[0].SignatureInfo[0].Author, ShouldEqual, string(publicKeyContent))

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody([]byte("wrong content")).Post(baseURL + constants.FullMgmtCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		resp, err = client.R().Get(baseURL + constants.FullMgmtCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)

		resp, err = client.R().Post(baseURL + constants.FullMgmtCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
	})

	Convey("Verify mgmt routes enabled for uploading cosign public keys with auth configured", t, func() {
		globalDir := t.TempDir()

		testCreds := test.GetCredString("admin", "admin") + "\n" + test.GetCredString("test", "test")
		htpasswdPath := test.MakeHtpasswdFileFromString(testCreds)

		conf := config.New()
		port := test.GetFreePort()
		defaultValue := true

		conf.HTTP.Port = port
		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			AdminPolicy: config.Policy{
				Users:   []string{"admin"},
				Actions: []string{},
			},
		}
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = nil
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		baseURL := test.GetBaseURL(port)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		defer os.Remove(logFile.Name()) // cleanup
		So(err, ShouldBeNil)

		logger := log.NewLogger("debug", logFile.Name())
		writers := io.MultiWriter(os.Stdout, logFile)
		logger.Logger = logger.Output(writers)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(), "setting up mgmt routes", time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		// generate a keypair
		keyDir := t.TempDir()

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		_ = os.Chdir(keyDir)

		os.Setenv("COSIGN_PASSWORD", "")
		err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
		So(err, ShouldBeNil)

		_ = os.Chdir(cwd)

		publicKeyContent, err := os.ReadFile(path.Join(keyDir, "cosign.pub"))
		So(err, ShouldBeNil)
		So(publicKeyContent, ShouldNotBeNil)

		// fail to upload the public key without credentials
		client := resty.New()
		resp, err := client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullMgmtCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// fail to upload the public key with bad credentials
		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullMgmtCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// upload the public key using credentials and non-admin user
		resp, err = client.R().SetBasicAuth("test", "test").SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullMgmtCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// upload the public key using credentials and admin user
		resp, err = client.R().SetBasicAuth("admin", "admin").SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullMgmtCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})

	Convey("Verify failures when saving uploaded certificates and public keys", t, func() {
		globalDir := t.TempDir()
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port
		baseURL := test.GetBaseURL(port)

		So(err, ShouldBeNil)
		defaultValue := true

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		rootDir := t.TempDir()

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(rootDir)

		// generate Notation cert
		err = test.GenerateNotationCerts(rootDir, "test")
		So(err, ShouldBeNil)

		certificateContent, err := os.ReadFile(path.Join(rootDir, "notation/localkeys", "test.crt"))
		So(err, ShouldBeNil)
		So(certificateContent, ShouldNotBeNil)

		// generate Cosign keys
		keyDir := t.TempDir()

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		_ = os.Chdir(keyDir)

		os.Setenv("COSIGN_PASSWORD", "")
		err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
		So(err, ShouldBeNil)

		_ = os.Chdir(cwd)

		publicKeyContent, err := os.ReadFile(path.Join(keyDir, "cosign.pub"))
		So(err, ShouldBeNil)
		So(publicKeyContent, ShouldNotBeNil)

		// Make sure the write to disk fails
		So(os.Chmod(globalDir, 0o000), ShouldBeNil)
		defer func() {
			So(os.Chmod(globalDir, 0o755), ShouldBeNil)
		}()

		client := resty.New()
		resp, err := client.R().SetHeader("Content-type", "application/octet-stream").
			SetQueryParam("truststoreName", "test").
			SetBody(certificateContent).Post(baseURL + constants.FullMgmtNotation)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)

		resp, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBody(publicKeyContent).Post(baseURL + constants.FullMgmtCosign)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
	})
}

type errReader int

func (errReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("test error") //nolint:goerr113
}

func TestSignatureHandlers(t *testing.T) {
	conf := config.New()
	log := log.NewLogger("debug", "")

	mgmt := extensions.Mgmt{
		Conf: conf,
		Log:  log,
	}

	Convey("Test error handling when Cosign handler reads the request body", t, func() {
		request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPost, "baseURL", errReader(0))
		response := httptest.NewRecorder()

		mgmt.HandleCosignPublicKeyUpload(response, request)

		resp := response.Result()
		defer resp.Body.Close()
		So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
	})

	Convey("Test error handling when Notation handler reads the request body", t, func() {
		request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPost, "baseURL", errReader(0))
		query := request.URL.Query()
		query.Add("truststoreName", "someName")
		request.URL.RawQuery = query.Encode()

		response := httptest.NewRecorder()
		mgmt.HandleNotationCertificateUpload(response, request)

		resp := response.Result()
		defer resp.Body.Close()
		So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
	})
}

func TestMgmtWithBearer(t *testing.T) {
	Convey("Make a new controller", t, func() {
		authorizedNamespace := "allowedrepo"
		unauthorizedNamespace := "notallowedrepo"
		authTestServer := test.MakeAuthTestServer(ServerKey, unauthorizedNamespace)
		defer authTestServer.Close()

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port

		aurl, err := url.Parse(authTestServer.URL)
		So(err, ShouldBeNil)

		conf.HTTP.Auth = &config.AuthConfig{
			Bearer: &config.BearerConfig{
				Cert:    ServerCert,
				Realm:   authTestServer.URL + "/auth/token",
				Service: aurl.Host,
			},
		}

		defaultValue := true

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Mgmt = &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{
				Enable: &defaultValue,
			},
		}

		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader := test.ParseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var goodToken test.AccessTokenResponse
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().SetHeader("Authorization",
			fmt.Sprintf("Bearer %s", goodToken.AccessToken)).Options(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

		resp, err = resty.R().Post(baseURL + "/v2/" + authorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = test.ParseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Post(baseURL + "/v2/" + authorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		resp, err = resty.R().
			Post(baseURL + "/v2/" + unauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = test.ParseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var badToken test.AccessTokenResponse
		err = json.Unmarshal(resp.Body(), &badToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", badToken.AccessToken)).
			Post(baseURL + "/v2/" + unauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// test mgmt route
		resp, err = resty.R().Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.DistSpecVersion, ShouldResemble, conf.DistSpecVersion)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, conf.HTTP.Auth.Bearer.Realm)
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, conf.HTTP.Auth.Bearer.Service)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)

		resp, err = resty.R().SetBasicAuth("", "").Get(baseURL + constants.FullMgmtAuth)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp = extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.DistSpecVersion, ShouldResemble, conf.DistSpecVersion)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, conf.HTTP.Auth.Bearer.Realm)
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, conf.HTTP.Auth.Bearer.Service)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
	})
}

func TestAllowedMethodsHeaderMgmt(t *testing.T) {
	defaultVal := true

	Convey("Test http options response", t, func() {
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{
			Mgmt: &extconf.MgmtConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			},
		}
		baseURL := test.GetBaseURL(port)

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctrlManager := test.NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)
		defer ctrlManager.StopServer()

		resp, _ := resty.R().Options(baseURL + constants.FullMgmtAuth)
		So(resp, ShouldNotBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "GET,OPTIONS")
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

		resp, _ = resty.R().Options(baseURL + constants.FullMgmtCosign)
		So(resp, ShouldNotBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "POST,OPTIONS")
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

		resp, _ = resty.R().Options(baseURL + constants.FullMgmtNotation)
		So(resp, ShouldNotBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "POST,OPTIONS")
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
	})
}
