package helper

import (
	"crypto/tls"
	"net/http"
	"net/url"

	configuration "github.com/3scale/3scale-operator/controllers/configuration"
	"github.com/3scale/3scale-operator/pkg/helper"

	threescaleapi "github.com/3scale/3scale-porta-go-client/client"
)

const (
	HTTP_VERBOSE_ENVVAR = "THREESCALE_DEBUG"
)

type ProviderAccount struct {
	AdminURLStr string
	Token       string
}

// PortaClient instantiates a ThreeScaleClient from a ProviderAccount.
// When insecureSkipVerify is true, the CA bundle is ignored and an insecure
// client is used instead.
func PortaClient(providerAccount *ProviderAccount, insecureSkipVerify bool) (*threescaleapi.ThreeScaleClient, error) {
	return PortaClientFromURLString(providerAccount.AdminURLStr, providerAccount.Token, insecureSkipVerify)
}

// PortaClientFromURLString instantiates a ThreeScaleClient from an admin URL string
// and access token.  When insecureSkipVerify is true, the CA bundle is ignored.
func PortaClientFromURLString(adminURLStr, token string, insecureSkipVerify bool) (*threescaleapi.ThreeScaleClient, error) {
	adminURL, err := url.Parse(adminURLStr)
	if err != nil {
		return nil, err
	}
	return PortaClientFromURL(adminURL, token, insecureSkipVerify)
}

// PortaClientFromURL instantiates a ThreeScaleClient from an admin URL
// and access token.  When insecureSkipVerify is true, certificate verification
// is disabled regardless of the configured CA bundle.
// Note: Callers must re-create the client on each reconcile cycle to pick up CA rotations.
func PortaClientFromURL(url *url.URL, token string, insecureSkipVerify bool) (*threescaleapi.ThreeScaleClient, error) {
	adminPortal, err := threescaleapi.NewAdminPortal(url.Scheme, url.Hostname(), helper.PortFromURL(url))
	if err != nil {
		return nil, err
	}
	var transport http.RoundTripper = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{ //nolint:gosec // G402: InsecureSkipVerify is intentional and user-controlled
			RootCAs:            configuration.GetRootCAs(),
			InsecureSkipVerify: insecureSkipVerify,
		},
	}
	if helper.GetEnvVar(HTTP_VERBOSE_ENVVAR, "0") == "1" {
		transport = &helper.Transport{Transport: transport}
	}

	return threescaleapi.NewThreeScale(adminPortal, token, &http.Client{Transport: transport}), nil
}

// GetInsecureSkipVerifyAnnotation extracts the insecure_skip_verify annotation from an object
func GetInsecureSkipVerifyAnnotation(annotations map[string]string) bool {
	insecureSkipVerify, ok := annotations["insecure_skip_verify"]
	if ok && insecureSkipVerify == "true" {
		return true
	}
	return false
}
