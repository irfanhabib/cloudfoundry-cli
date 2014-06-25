package securitygroup_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestAppSecurityGroup(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SecurityGroup Suite")
}
