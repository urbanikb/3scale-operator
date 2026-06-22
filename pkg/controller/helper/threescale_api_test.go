package helper

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	threescaleapi "github.com/3scale/3scale-porta-go-client/client"

	"github.com/3scale/3scale-operator/pkg/testhelper"
)

func backendListHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(threescaleapi.BackendApiList{}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	})
}

func TestPortaClient(t *testing.T) {
	tests := []struct {
		name            string
		account         *ProviderAccount
		wantErrContains string
	}{
		{
			name:            "invalid URL is rejected",
			account:         &ProviderAccount{AdminURLStr: ":foo", Token: "some token"},
			wantErrContains: "missing protocol scheme",
		},
		{
			name:    "valid URL produces a usable client",
			account: &ProviderAccount{AdminURLStr: "http://somedomain.example.com", Token: "some token"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PortaClient(tc.account, false)
			if tc.wantErrContains != "" {
				assert(t, err != nil, "error should not be nil")
				assert(t, strings.Contains(err.Error(), tc.wantErrContains),
					"expected %q in error, got: %v", tc.wantErrContains, err)
			} else {
				ok(t, err)
			}
		})
	}
}

func TestPortaClientFromURLString(t *testing.T) {
	tests := []struct {
		name            string
		rawURL          string
		wantErrContains string
	}{
		{
			name:            "invalid URL is rejected",
			rawURL:          ":foo",
			wantErrContains: "missing protocol scheme",
		},
		{
			name:   "valid URL produces a usable client",
			rawURL: "http://somedomain.example.com",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PortaClientFromURLString(tc.rawURL, "some token", false)
			if tc.wantErrContains != "" {
				assert(t, err != nil, "error should not be nil")
				assert(t, strings.Contains(err.Error(), tc.wantErrContains),
					"expected %q in error, got: %v", tc.wantErrContains, err)
			} else {
				ok(t, err)
			}
		})
	}
}

func TestPortaClientFromURL(t *testing.T) {
	tests := []struct {
		name                  string
		buildURL              func(t *testing.T, srv *httptest.Server) *url.URL
		insecureSkipVerify    bool
		setupCA               func(t *testing.T, srv *httptest.Server)
		wantClientErrContains string
		requestErrContains    string
	}{
		{
			name: "empty URL is rejected",
			buildURL: func(t *testing.T, _ *httptest.Server) *url.URL {
				return &url.URL{}
			},
			wantClientErrContains: "missing protocol scheme",
		},
		{
			name: "untrusted server certificate is rejected",
			buildURL: func(t *testing.T, srv *httptest.Server) *url.URL {
				u, err := url.Parse(srv.URL)
				ok(t, err)
				return u
			},
			setupCA: func(t *testing.T, _ *httptest.Server) {
				testhelper.SeedRootCAsForTest(t, nil)
			},
			requestErrContains: "x509: certificate signed by unknown authority",
		},
		{
			name: "matching CA allows a successful request",
			buildURL: func(t *testing.T, srv *httptest.Server) *url.URL {
				u, err := url.Parse(srv.URL)
				ok(t, err)
				return u
			},
			setupCA: func(t *testing.T, srv *httptest.Server) {
				pool := x509.NewCertPool()
				for _, cert := range srv.TLS.Certificates {
					for _, c := range cert.Certificate {
						parsed, err := x509.ParseCertificate(c)
						ok(t, err)
						pool.AddCert(parsed)
					}
				}
				testhelper.SeedRootCAsForTest(t, pool)
			},
		},
		{
			name: "insecureSkipVerify accepts untrusted certificate",
			buildURL: func(t *testing.T, srv *httptest.Server) *url.URL {
				u, err := url.Parse(srv.URL)
				ok(t, err)
				return u
			},
			insecureSkipVerify: true,
			setupCA: func(t *testing.T, _ *httptest.Server) {
				testhelper.SeedRootCAsForTest(t, nil)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(backendListHandler(t))
			defer srv.Close()

			if tc.setupCA != nil {
				tc.setupCA(t, srv)
			}

			u := tc.buildURL(t, srv)

			c, err := PortaClientFromURL(u, "token", tc.insecureSkipVerify)
			if tc.wantClientErrContains != "" {
				assert(t, err != nil, "expected client construction error, got nil")
				assert(t, strings.Contains(err.Error(), tc.wantClientErrContains),
					"expected %q in error, got: %v", tc.wantClientErrContains, err)
				return
			}
			ok(t, err)

			_, reqErr := c.ListBackendApis()
			if tc.requestErrContains != "" {
				assert(t, reqErr != nil, "expected request error, got nil")
				assert(t, strings.Contains(reqErr.Error(), tc.requestErrContains),
					"expected %q in error, got: %v", tc.requestErrContains, reqErr)
			} else {
				ok(t, reqErr)
			}
		})
	}
}
