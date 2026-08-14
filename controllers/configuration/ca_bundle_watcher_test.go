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

package configuration_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakectrlclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/3scale/3scale-operator/controllers/configuration"
	"github.com/3scale/3scale-operator/pkg/testhelper"
)

// errorInjectingClient makes r.Get return a non-NotFound error so the
// reconciler propagates it to the workqueue.
type errorInjectingClient struct {
	client.Client
	getErr error
}

func (e *errorInjectingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return e.getErr
}

// generateSelfSignedCert creates a minimal self-signed RSA certificate and
// returns its PEM-encoded DER bytes. It is not a real secret and carries no
// trust outside the test suite.
func generateSelfSignedCert(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return der
}

func encodePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCABundleWatcher_Reconcile(t *testing.T) {
	certDER := generateSelfSignedCert(t, "test-ca")
	certPEM := encodePEM(certDER)

	seedDER := generateSelfSignedCert(t, "test-ca-at-start")
	seedPool := x509.NewCertPool()
	seedCert, err := x509.ParseCertificate(seedDER)
	if err != nil {
		t.Fatalf("parse seed cert: %v", err)
	}
	seedPool.AddCert(seedCert)

	validCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: configuration.CABundleConfigMapName},
		Data:       map[string]string{configuration.CABundleConfigMapKey: string(certPEM)},
	}
	emptyCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: configuration.CABundleConfigMapName},
		Data:       map[string]string{configuration.CABundleConfigMapKey: ""},
	}
	invalidCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: configuration.CABundleConfigMapName},
		Data:       map[string]string{configuration.CABundleConfigMapKey: "not-a-pem"},
	}
	keyAbsentCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: configuration.CABundleConfigMapName},
		Data:       map[string]string{},
	}

	tests := []struct {
		name         string
		objects      []runtime.Object
		seedPool     *x509.CertPool
		injectGetErr bool
		wantErr      bool
		wantErrMsg   string
		check        func(t *testing.T, rec *record.FakeRecorder)
	}{
		{
			name:     "ConfigMap not found — SetRootCAs(nil), no error, no event",
			objects:  []runtime.Object{},
			seedPool: seedPool,
			wantErr:  false,
			check: func(t *testing.T, rec *record.FakeRecorder) {
				if configuration.GetRootCAs() != nil {
					t.Error("expected GetRootCAs() == nil after not-found")
				}
				assertNoEventW(t, rec)
			},
		},
		{
			name:         "generic Get error — error returned, CAs unchanged, no event",
			objects:      []runtime.Object{},
			seedPool:     seedPool,
			injectGetErr: true,
			wantErr:      true,
			wantErrMsg:   "synthetic server error",
			check: func(t *testing.T, rec *record.FakeRecorder) {
				pool := configuration.GetRootCAs()
				if pool == nil {
					t.Error("expected GetRootCAs() to remain non-nil (seeded value)")
				} else if !pool.Equal(seedPool) {
					t.Error("loaded CA pool does not contain the expected certificate")
				}
				assertNoEventW(t, rec)
			},
		},
		{
			name:     "ConfigMap present, key present but empty — Warning event, no error, CAs unchanged",
			objects:  []runtime.Object{emptyCM},
			seedPool: seedPool,
			wantErr:  false,
			check: func(t *testing.T, rec *record.FakeRecorder) {
				pool := configuration.GetRootCAs()
				if pool == nil {
					t.Error("expected GetRootCAs() to remain non-nil (kept previous config)")
				} else if !pool.Equal(seedPool) {
					t.Error("loaded CA pool does not contain the expected certificate")
				}

				msg := drainOneEventW(t, rec)
				for _, sub := range []string{"Warning", "InvalidCABundle", "InvalidCAFormat: key \"ca-bundle.crt\" in ConfigMap test-ns/threescale-ca-bundle is empty"} {
					if !strings.Contains(msg, sub) {
						t.Errorf("event %q missing expected substring %q", msg, sub)
					}
				}
				assertNoEventW(t, rec)
			},
		},
		{
			name:     "ConfigMap present, PEM invalid — Warning event, no error, CAs unchanged",
			objects:  []runtime.Object{invalidCM},
			seedPool: seedPool,
			wantErr:  false,
			check: func(t *testing.T, rec *record.FakeRecorder) {
				pool := configuration.GetRootCAs()
				if pool == nil {
					t.Error("expected GetRootCAs() to remain non-nil (kept previous config)")
				} else if !pool.Equal(seedPool) {
					t.Error("loaded CA pool does not contain the expected certificate")
				}
				msg := drainOneEventW(t, rec)
				for _, sub := range []string{"Warning", "InvalidCABundle", "InvalidCAFormat: no valid PEM-encoded certificates found in CA bundle"} {
					if !strings.Contains(msg, sub) {
						t.Errorf("event %q missing expected substring %q", msg, sub)
					}
				}
				assertNoEventW(t, rec)
			},
		},
		{
			name:     "ConfigMap present, key absent — SetRootCAs(nil), no error, no event",
			objects:  []runtime.Object{keyAbsentCM},
			seedPool: seedPool,
			wantErr:  false,
			check: func(t *testing.T, rec *record.FakeRecorder) {
				if configuration.GetRootCAs() != nil {
					t.Error("expected GetRootCAs() == nil after key-absent")
				}
				assertNoEventW(t, rec)
			},
		},
		{
			name:    "ConfigMap present, valid PEM — SetRootCAs(pool), no error, no event",
			objects: []runtime.Object{validCM},
			wantErr: false,
			check: func(t *testing.T, rec *record.FakeRecorder) {
				pool := configuration.GetRootCAs()
				if pool == nil {
					t.Fatal("expected GetRootCAs() != nil after valid PEM")
				}
				cert, err := x509.ParseCertificate(certDER)
				if err != nil {
					t.Fatalf("parse test certificate: %v", err)
				}
				expected := x509.NewCertPool()
				expected.AddCert(cert)
				if !pool.Equal(expected) {
					t.Error("loaded CA pool does not contain the expected certificate")
				}
				assertNoEventW(t, rec)
			},
		},
		{
			name:     "ConfigMap present, valid PEM, replace seed case — SetRootCAs(pool), no error, no event",
			objects:  []runtime.Object{validCM},
			seedPool: seedPool,
			wantErr:  false,
			check: func(t *testing.T, rec *record.FakeRecorder) {
				pool := configuration.GetRootCAs()
				if pool == nil {
					t.Fatal("expected GetRootCAs() != nil after valid PEM")
				}
				cert, err := x509.ParseCertificate(certDER)
				if err != nil {
					t.Fatalf("parse test certificate: %v", err)
				}
				expected := x509.NewCertPool()
				expected.AddCert(cert)
				if !pool.Equal(expected) {
					t.Error("loaded CA pool does not contain the expected certificate")
				}
				assertNoEventW(t, rec)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Seed a known non-nil pool so "nil after Reconcile" assertions are unambiguous.
			testhelper.SeedRootCAsForTest(t, tc.seedPool)

			s := runtime.NewScheme()
			if err := corev1.AddToScheme(s); err != nil {
				t.Fatalf("AddToScheme corev1: %v", err)
			}

			cl := fakectrlclient.NewClientBuilder().
				WithScheme(s).
				WithRuntimeObjects(tc.objects...).
				Build()

			var cl2 client.Client = cl
			if tc.injectGetErr {
				cl2 = &errorInjectingClient{Client: cl, getErr: errors.New("synthetic server error")}
			}

			rec := record.NewFakeRecorder(10)
			watcher := &configuration.CABundleWatcher{
				Client:    cl2,
				Recorder:  rec,
				Namespace: "test-ns",
			}

			_, err := watcher.Reconcile(context.Background(), reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: "test-ns", Name: configuration.CABundleConfigMapName},
			})

			if (err != nil) != tc.wantErr {
				t.Errorf("wantErr=%v, got err=%v", tc.wantErr, err)
			}
			if tc.wantErrMsg != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErrMsg)) {
				t.Errorf("expected error containing %q, got %v", tc.wantErrMsg, err)
			}
			tc.check(t, rec)
		})
	}
}

// drainOneEventW reads one event from the recorder and returns it.
// Calls t.Fatal immediately if the channel is empty.
func drainOneEventW(t *testing.T, rec *record.FakeRecorder) string {
	t.Helper()
	select {
	case msg := <-rec.Events:
		return msg
	default:
		t.Fatal("expected one event on recorder, but channel was empty")
		return ""
	}
}

// assertNoEventW fails the test if any event remains on the recorder.
func assertNoEventW(t *testing.T, rec *record.FakeRecorder) {
	t.Helper()
	select {
	case msg := <-rec.Events:
		t.Errorf("unexpected event: %q", msg)
	default:
	}
}
