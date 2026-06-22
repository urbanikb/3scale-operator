/*
Copyright 2026 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package testhelper provides shared test utilities that must be importable
// from multiple test packages across the repository.
package testhelper

import (
	"crypto/x509"
	"testing"

	configuration "github.com/3scale/3scale-operator/controllers/configuration"
)

// SeedRootCAsForTest seeds the package-level CA pool to pool and restores the
// previous value via t.Cleanup.
//
// SetRootCAs/GetRootCAs mutate process-level global state, so any test that
// calls this helper MUST NOT call t.Parallel().  t.Setenv is the mechanism
// that enforces this: it panics when called from inside a parallel test,
// making the constraint mechanical rather than advisory.
func SeedRootCAsForTest(t testing.TB, pool *x509.CertPool) {
	t.Helper()
	t.Setenv("_TEST_TLS_GUARD", "1")
	prev := configuration.GetRootCAs()
	configuration.SetRootCAs(pool)
	t.Cleanup(func() { configuration.SetRootCAs(prev) })
}
