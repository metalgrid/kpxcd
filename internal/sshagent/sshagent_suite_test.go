//go:build linux

package sshagent

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSshagent(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sshagent Suite")
}
