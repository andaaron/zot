package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/docker/distribution/registry/storage/driver"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
	common "zotregistry.io/zot/pkg/storage/common"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/storage/s3"
	storageTypes "zotregistry.io/zot/pkg/storage/types"
	. "zotregistry.io/zot/pkg/test/image-utils"
	"zotregistry.io/zot/pkg/test/mocks"
	tskip "zotregistry.io/zot/pkg/test/skip"
)

const (
	repoName = "test"
	tag      = "1.0"
)

var errUnexpectedError = errors.New("unexpected err")

func TestLocalCheckAllBlobsIntegrity(t *testing.T) {
	Convey("test with local storage", t, func() {
		tdir := t.TempDir()
		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     tdir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		driver := local.New(true)
		imgStore := local.NewImageStore(tdir, true, true, log, metrics, nil, cacheDriver)

		RunCheckAllBlobsIntegrityTests(t, imgStore, driver, log)
	})
}

func TestS3CheckAllBlobsIntegrity(t *testing.T) {
	tskip.SkipS3(t)

	Convey("test with S3 storage", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())
		tdir := t.TempDir()
		log := log.NewLogger("debug", "")

		var store driver.StorageDriver
		store, imgStore, _ := createObjectsStore(testDir, tdir)
		defer cleanupStorage(store, testDir)

		driver := s3.New(store)

		RunCheckAllBlobsIntegrityTests(t, imgStore, driver, log)
	})
}

func RunCheckAllBlobsIntegrityTests( //nolint: thelper
	t *testing.T, imgStore storageTypes.ImageStore, driver storageTypes.Driver, log log.Logger,
) {
	Convey("Scrub only one repo", func() {
		// initialize repo
		err := imgStore.InitRepo(repoName)
		So(err, ShouldBeNil)
		ok := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
		So(ok, ShouldBeTrue)
		storeCtlr := storage.StoreController{}
		storeCtlr.DefaultStore = imgStore
		So(storeCtlr.GetImageStore(repoName), ShouldResemble, imgStore)

		image := CreateRandomImage()

		err = WriteImageToFileSystem(image, repoName, tag, storeCtlr)
		So(err, ShouldBeNil)

		Convey("Blobs integrity not affected", func() {
			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
		})

		Convey("Blobs integrity with context done", func() {
			buff := bytes.NewBufferString("")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			res, err := storeCtlr.CheckAllBlobsIntegrity(ctx)
			res.PrintScrubResults(buff)
			So(err, ShouldNotBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldNotContainSubstring, "test 1.0 ok")
		})

		Convey("Manifest integrity affected", func() {
			// get content of manifest file
			content, _, _, err := imgStore.GetImageManifest(repoName, image.ManifestDescriptor.Digest.String())
			So(err, ShouldBeNil)

			// delete content of manifest file
			manifestDig := image.ManifestDescriptor.Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			defer func() {
				// put manifest content back to file
				_, err = driver.WriteFile(manifestFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			// verify error message
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s blob not found", manifestDig))

			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)
			manifestDescriptor := index.Manifests[0]

			imageRes := storage.CheckLayers(context.Background(), repoName, tag, manifestDescriptor, imgStore)
			So(imageRes.Status, ShouldEqual, "affected")
			So(imageRes.Error, ShouldEqual, "blob not found")

			_, err = driver.WriteFile(manifestFile, []byte("invalid content"))
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			// verify error message
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s invalid manifest content", manifestDig))

			index, err = common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)
			manifestDescriptor = index.Manifests[0]

			imageRes = storage.CheckLayers(context.Background(), repoName, tag, manifestDescriptor, imgStore)
			So(imageRes.Status, ShouldEqual, "affected")
			So(imageRes.Error, ShouldEqual, "invalid manifest content")
		})

		Convey("Config integrity affected", func() {
			// get content of config file
			content, err := imgStore.GetBlobContent(repoName, image.ConfigDescriptor.Digest)
			So(err, ShouldBeNil)

			// delete content of config file
			configDig := image.ConfigDescriptor.Digest.Encoded()
			configFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", configDig)
			err = driver.Delete(configFile)
			So(err, ShouldBeNil)

			defer func() {
				// put config content back to file
				_, err = driver.WriteFile(configFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s blob not found", configDig))

			_, err = driver.WriteFile(configFile, []byte("invalid content"))
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s invalid server config", configDig))
		})

		Convey("Layers integrity affected", func() {
			// get content of layer
			content, err := imgStore.GetBlobContent(repoName, image.Manifest.Layers[0].Digest)
			So(err, ShouldBeNil)

			// delete content of layer file
			layerDig := image.Manifest.Layers[0].Digest.Encoded()
			layerFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", layerDig)
			_, err = driver.WriteFile(layerFile, []byte(" "))
			So(err, ShouldBeNil)

			defer func() {
				// put layer content back to file
				_, err = driver.WriteFile(layerFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s bad blob digest", layerDig))
		})

		Convey("Layer not found", func() {
			// get content of layer
			content, err := imgStore.GetBlobContent(repoName, image.Manifest.Layers[0].Digest)
			So(err, ShouldBeNil)

			// change layer file permissions
			layerDig := image.Manifest.Layers[0].Digest.Encoded()
			repoDir := path.Join(imgStore.RootDir(), repoName)
			layerFile := path.Join(repoDir, "/blobs/sha256", layerDig)
			err = driver.Delete(layerFile)
			So(err, ShouldBeNil)

			defer func() {
				_, err := driver.WriteFile(layerFile, content)
				So(err, ShouldBeNil)
			}()

			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)
			manifestDescriptor := index.Manifests[0]

			imageRes := storage.CheckLayers(context.Background(), repoName, tag, manifestDescriptor, imgStore)
			So(imageRes.Status, ShouldEqual, "affected")
			So(imageRes.Error, ShouldEqual, "blob not found")

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s blob not found", layerDig))
		})

		Convey("Scrub index", func() {
			newImage := CreateRandomImage()
			newManifestDigest := newImage.ManifestDescriptor.Digest

			err = WriteImageToFileSystem(newImage, repoName, "2.0", storeCtlr)
			So(err, ShouldBeNil)

			idx, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(idx, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			var index ispec.Index
			index.SchemaVersion = 2
			index.Subject = &manifestDescriptor
			index.Manifests = []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    newManifestDigest,
					Size:      newImage.ManifestDescriptor.Size,
				},
			}

			indexBlob, err := json.Marshal(index)
			So(err, ShouldBeNil)
			indexDigest, _, err := imgStore.PutImageManifest(repoName, "", ispec.MediaTypeImageIndex, indexBlob)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
			So(actual, ShouldContainSubstring, "test ok")

			// test scrub context done
			buff = bytes.NewBufferString("")

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			res, err = storeCtlr.CheckAllBlobsIntegrity(ctx)
			res.PrintScrubResults(buff)
			So(err, ShouldNotBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldNotContainSubstring, "test 1.0 ok")
			So(actual, ShouldNotContainSubstring, "test ok")

			// test scrub index - errors
			// delete content of manifest file
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", newManifestDigest.Encoded())
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")

			indexFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", indexDigest.Encoded())
			err = driver.Delete(indexFile)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")

			index.Manifests[0].MediaType = "invalid"
			indexBlob, err = json.Marshal(index)
			So(err, ShouldBeNil)

			_, err = driver.WriteFile(indexFile, indexBlob)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			_, err = storage.CheckManifestAndConfig(repoName, index.Manifests[0], imgStore)
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrBadManifest)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")

			_, err = driver.WriteFile(indexFile, []byte("invalid cotent"))
			So(err, ShouldBeNil)

			defer func() {
				err := driver.Delete(indexFile)
				So(err, ShouldBeNil)
			}()

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")
		})

		Convey("Manifest not found", func() {
			// delete manifest file
			manifestDig := image.ManifestDescriptor.Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s blob not found", manifestDig))

			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)
			manifestDescriptor := index.Manifests[0]

			imageRes := storage.CheckLayers(context.Background(), repoName, tag, manifestDescriptor, imgStore)
			So(imageRes.Status, ShouldEqual, "affected")
			So(imageRes.Error, ShouldContainSubstring, "blob not found")
		})

		Convey("use the result of an already scrubed manifest which is the subject of the current manifest", func() {
			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			err = WriteImageToFileSystem(CreateDefaultImageWith().Subject(&manifestDescriptor).Build(),
				repoName, "0.0.1", storeCtlr)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
			So(actual, ShouldContainSubstring, "test 0.0.1 ok")
		})
	})

	Convey("test errors", func() {
		mockedImgStore := mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) {
				return []string{repoName}, nil
			},
			ValidateRepoFn: func(name string) (bool, error) {
				return false, nil
			},
		}

		storeController := storage.StoreController{}
		storeController.DefaultStore = mockedImgStore

		_, err := storeController.CheckAllBlobsIntegrity(context.Background())
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrRepoBadLayout)

		mockedImgStore = mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) {
				return []string{repoName}, nil
			},
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return []byte{}, errUnexpectedError
			},
		}

		storeController.DefaultStore = mockedImgStore

		_, err = storeController.CheckAllBlobsIntegrity(context.Background())
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errUnexpectedError)

		manifestDigest := godigest.FromString("abcd")

		mockedImgStore = mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) {
				return []string{repoName}, nil
			},
			GetIndexContentFn: func(repo string) ([]byte, error) {
				var index ispec.Index
				index.SchemaVersion = 2
				index.Manifests = []ispec.Descriptor{
					{
						MediaType:   "InvalidMediaType",
						Digest:      manifestDigest,
						Size:        int64(100),
						Annotations: map[string]string{ispec.AnnotationRefName: "1.0"},
					},
				}

				return json.Marshal(index)
			},
		}

		storeController.DefaultStore = mockedImgStore

		res, err := storeController.CheckAllBlobsIntegrity(context.Background())
		So(err, ShouldBeNil)

		buff := bytes.NewBufferString("")
		res.PrintScrubResults(buff)

		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
		So(actual, ShouldContainSubstring, fmt.Sprintf("%s 1.0 affected %s invalid manifest content",
			repoName, manifestDigest.Encoded()))
	})
}
