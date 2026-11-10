//go:build linux

package fido2

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestFido2(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Fido2 Suite")
}
