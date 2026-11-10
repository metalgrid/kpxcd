//go:build linux

package dbusapi

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestDbusapi(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Dbusapi Suite")
}
