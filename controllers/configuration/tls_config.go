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

package configuration

import (
	"crypto/x509"
	"sync"
)

// currentRootCAs is the package-level CA pool derived from the most recently
// reconciled threescale-ca-bundle ConfigMap.
// nil means "no custom CA bundle" — callers should use system roots.
var currentRootCAs *x509.CertPool

var tlsConfigMu sync.RWMutex

// SetRootCAs replaces the current package-level CA pool.
// Pass nil to revert to system roots (e.g. when the ConfigMap is deleted).
func SetRootCAs(pool *x509.CertPool) {
	tlsConfigMu.Lock()
	currentRootCAs = pool
	tlsConfigMu.Unlock()
}

// GetRootCAs returns the current package-level CA pool, or nil if no bundle
// has been configured. Callers construct their own tls.Config and set RootCAs
// from the returned value. The pool must not be modified.
func GetRootCAs() *x509.CertPool {
	tlsConfigMu.RLock()
	defer tlsConfigMu.RUnlock()
	return currentRootCAs
}
