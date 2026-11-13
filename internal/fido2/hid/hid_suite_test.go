//go:build linux

package hid

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestHid(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Hid Suite")
}
