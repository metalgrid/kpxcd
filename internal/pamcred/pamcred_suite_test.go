//go:build linux

package pamcred

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestPamcred(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Pamcred Suite")
}
