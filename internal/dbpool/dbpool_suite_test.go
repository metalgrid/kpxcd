//go:build linux

package dbpool

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestDbpool(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Dbpool Suite")
}
