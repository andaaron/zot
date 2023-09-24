//go:build search && ui
// +build search,ui

package extensions_test

import (
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	testc "zotregistry.io/zot/pkg/test/common"
	"zotregistry.io/zot/pkg/test/deprecated"
	. "zotregistry.io/zot/pkg/test/image-utils"
)

func TestUIExtension(t *testing.T) {
	Convey("Verify zot with UI extension starts successfully", t, func() {
		conf := config.New()
		port := testc.GetFreePort()
		baseURL := testc.GetBaseURL(port)
		conf.HTTP.Port = port

		// we won't use the logging config feature as we want logs in both
		// stdout and a file
		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		So(err, ShouldBeNil)
		logPath := logFile.Name()
		defer os.Remove(logPath)

		writers := io.MultiWriter(os.Stdout, logFile)

		defaultValue := true

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.UI = &extconf.UIConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultValue},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

		ctlrManager := testc.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)

		found, err := testc.ReadLogFileAndSearchString(logPath, "\"UI\":{\"Enable\":true}", 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = testc.ReadLogFileAndSearchString(logPath, "setting up ui routes", 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		cfg, layers, manifest, err := deprecated.GetImageComponents(1) //nolint:staticcheck
		So(err, ShouldBeNil)

		repoName := "test-repo"
		tagName := "test-tag"

		// Upload a test image
		err = UploadImage(
			Image{
				Config:   cfg,
				Layers:   layers,
				Manifest: manifest,
			}, baseURL, repoName, tagName)
		So(err, ShouldBeNil)

		resp, err := resty.R().Get(baseURL + "/home")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/image/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/image/" + repoName)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/image/" + repoName + "/tag/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/image/" + repoName + "/tag/" + tagName)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/badurl/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}
