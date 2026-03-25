package testserver

import (
	"github.com/formancehq/go-libs/v3/testing/deferred"
	ginkgo "github.com/onsi/ginkgo/v2"
)

func NewTestServer(configurationProvider func() Configuration) *deferred.Deferred[*Server] {
	d := deferred.New[*Server]()
	ginkgo.BeforeEach(func() {
		d.Reset()
		d.SetValue(New(ginkgo.GinkgoT(), configurationProvider()))
	})
	return d
}
