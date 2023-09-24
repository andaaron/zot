//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package deprecated_test

import (
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/test/deprecated"
	"zotregistry.io/zot/pkg/test/inject"
)

func TestGetImageComponents(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := inject.InjectFailure(0)
		if injected {
			_, _, _, err := deprecated.GetImageComponents(100)
			So(err, ShouldNotBeNil)
		}
	})
	Convey("finishes successfully", t, func() {
		_, _, _, err := deprecated.GetImageComponents(100)
		So(err, ShouldBeNil)
	})
}

func TestGetRandomImageComponents(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := inject.InjectFailure(0)
		if injected {
			_, _, _, err := deprecated.GetRandomImageComponents(100)
			So(err, ShouldNotBeNil)
		}
	})
}

func TestGetImageComponentsWithConfig(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := inject.InjectFailure(0)
		if injected {
			_, _, _, err := deprecated.GetImageComponentsWithConfig(ispec.Image{})
			So(err, ShouldNotBeNil)
		}
	})
}
