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
	"context"
	"crypto/x509"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	CABundleConfigMapName = "threescale-ca-bundle"
	CABundleConfigMapKey  = "ca-bundle.crt"
)

// CABundleWatcher watches the threescale-ca-bundle ConfigMap and updates the
// package-level CA pool via SetRootCAs on every successful reconcile.
type CABundleWatcher struct {
	client.Client
	Recorder  record.EventRecorder
	Namespace string
}

// SetupWithManager registers the controller with the manager.
func (r *CABundleWatcher) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("cabundlewatcher").
		// NeedLeaderElection is disabled so that every operator replica runs
		// this controller, not just the leader.  Each replica must load the CA
		// bundle into its own in-process TLS config.
		//
		// controller-runtime replays a synthetic Add event for every object
		// already in the informer cache when a controller starts, so a newly
		// promoted leader would pick up the bundle automatically.  Running on
		// all replicas avoids the small window between manager start and leader
		// promotion during which capability reconcilers could attempt outbound
		// TLS calls before the bundle has been loaded.  Those calls would fail
		// and requeue, but disabling leader election here eliminates the window
		// entirely.
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(false)}).
		For(&corev1.ConfigMap{}, builder.WithPredicates(predicate.NewPredicateFuncs(func(object client.Object) bool {
			return object.GetNamespace() == r.Namespace && object.GetName() == CABundleConfigMapName
		}))).
		Complete(r)
}

// Reconcile fetches the CA bundle ConfigMap and updates the package-level
// TLS config.  On an invalid bundle, the error is logged and recorded as a Warning event on
// the ConfigMap; the existing TLS config is left unchanged so capability
// controllers continue to operate with the last known good CA.
func (r *CABundleWatcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.LoggerFrom(ctx)

	cm := &corev1.ConfigMap{}
	err := r.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: CABundleConfigMapName}, cm)
	if err != nil {
		if apierrors.IsNotFound(err) {
			SetRootCAs(nil)
			logger.Info("CA bundle ConfigMap not found; using system default CAs", "namespace", r.Namespace, "configmap", CABundleConfigMapName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	pool, parseErr := parseBundleFromConfigMap(cm)
	if parseErr != nil {
		logger.Error(parseErr, "CA bundle ConfigMap contains an invalid certificate bundle; keeping previous TLS config")
		if r.Recorder != nil {
			r.Recorder.Eventf(cm, corev1.EventTypeWarning, "InvalidCABundle", "%v", parseErr)
		}
		return ctrl.Result{}, nil
	}

	if pool == nil {
		SetRootCAs(nil)
		logger.Info("CA bundle ConfigMap key absent; using system default CAs", "namespace", r.Namespace, "configmap", CABundleConfigMapName, "key", CABundleConfigMapKey)
		return ctrl.Result{}, nil
	}

	SetRootCAs(pool)
	logger.Info("CA bundle updated and applied", "namespace", r.Namespace, "configmap", CABundleConfigMapName)
	return ctrl.Result{}, nil
}

// parseBundleFromConfigMap parses the CA bundle from a ConfigMap and returns a
// *x509.CertPool.  Returns nil, nil if the key is absent (no custom bundle
// configured).  Returns an error if the PEM data is present but invalid.
func parseBundleFromConfigMap(cm *corev1.ConfigMap) (*x509.CertPool, error) {
	val, exists := cm.Data[CABundleConfigMapKey]
	if !exists {
		return nil, nil // no bundle configured — use system roots
	}

	if len(val) == 0 {
		return nil, fmt.Errorf("InvalidCAFormat: key %q in ConfigMap %s/%s is empty", CABundleConfigMapKey, cm.Namespace, cm.Name)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(val)) {
		return nil, fmt.Errorf("InvalidCAFormat: no valid PEM-encoded certificates found in CA bundle")
	}

	return certPool, nil
}
