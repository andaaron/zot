package http_utils_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	httputils "zotregistry.io/zot/pkg/test/http-utils"
)

func TestBearerServer(t *testing.T) {
	Convey("test MakeAuthTestServer() no serve key", t, func() {
		So(func() { httputils.MakeAuthTestServer("", "") }, ShouldPanic)
	})
}
