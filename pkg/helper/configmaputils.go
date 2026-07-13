package helper

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const CABundleKey = "ca-bundle.crt"

// ValidateCABundleConfigMap fetches the ConfigMap identified by nn and verifies
// it contains the required CA bundle key. Returns the ConfigMap on success, or
// an error if the name is empty, the ConfigMap is not found, or the key is absent.
func ValidateCABundleConfigMap(nn types.NamespacedName, cl k8sclient.Client) (*v1.ConfigMap, error) {
	if nn.Name == "" {
		return nil, fmt.Errorf("configmap name is required")
	}

	cm := &v1.ConfigMap{}
	err := cl.Get(context.TODO(), nn, cm)
	if err != nil {
		return nil, err
	}

	if _, ok := cm.Data[CABundleKey]; !ok {
		return nil, fmt.Errorf("required configmap key, %s, not found", CABundleKey)
	}

	return cm, nil
}
