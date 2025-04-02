//go:build it

package suite_test

import (
	"encoding/json"
	"github.com/formancehq/go-libs/v2/logging"
	"github.com/formancehq/go-libs/v2/testing/docker"
	. "github.com/formancehq/go-libs/v2/testing/platform/pgtesting"
	. "github.com/formancehq/go-libs/v2/testing/utils"
	"github.com/oauth2-proxy/mockoidc"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestExamples(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Wallets Testing Suite")
}

var (
	dockerPool = NewDeferred[*docker.Pool]()
	debug      = os.Getenv("DEBUG") == "true"
	logger     = logging.NewDefaultLogger(GinkgoWriter, debug, false, false)
	mockOIDC   *mockoidc.MockOIDC
	pgServer   = NewDeferred[*PostgresServer]()
)

type ParallelExecutionContext struct{}

var _ = SynchronizedBeforeSuite(func() []byte {
	By("Initializing docker pool")
	dockerPool.SetValue(docker.NewPool(GinkgoT(), logger))

	pgServer.SetValue(CreatePostgresServer(
		GinkgoT(),
		dockerPool.GetValue(),
		WithPGStatsExtension(),
		WithPGCrypto(),
	))

	data, err := json.Marshal(ParallelExecutionContext{})
	Expect(err).To(BeNil())

	return data
}, func(data []byte) {
	pec := ParallelExecutionContext{}
	err := json.Unmarshal(data, &pec)
	Expect(err).To(BeNil())

	mockOIDC, err = mockoidc.Run()
	Expect(err).To(BeNil())
})
