//go:build linux

package secretservice

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSecretService(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SecretService Suite")
}
