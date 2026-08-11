package integration

import (
	"fmt"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// verifyNoDeploymentUpdates asserts that the reconcile counter recorded exactly
// the expected number of deployment updates, then resets the counter so the
// next measurement window starts from zero.
//
// Before the synthetic trigger this should be 0 (no perpetual reconcile during
// initial deployment). After the synthetic trigger it should be exactly 1 (the
// operator corrected the drift and stopped).
func verifyNoDeploymentUpdates(expected int) {
	updateCounts := reconcileCounter.GetUpdateCounts()
	totalUpdates := reconcileCounter.GetTotalUpdates()

	Expect(totalUpdates).To(Equal(expected),
		deploymentUpdateDetail(updateCounts, totalUpdates, expected))

	reconcileCounter.Reset()
}

// deploymentUpdateDetail builds a human-readable breakdown for use in a Gomega
// failure message so the offending deployments are immediately visible.
func deploymentUpdateDetail(counts map[string]int, total, expected int) string {
	sb := fmt.Sprintf("total deployment updates %d, expected %d; per-deployment breakdown:\n",
		total, expected)
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sb += fmt.Sprintf("  %s: %d\n", n, counts[n])
	}
	return sb
}

var _ = Describe // suppress unused import lint for ginkgo dot-import
