# Configuring a custom CA bundle

The 3scale operator supports injecting a custom CA certificate bundle into the TLS configuration used when communicating with external HTTPS services. This is done via a well-known `ConfigMap` that the operator watches in the same namespace.

When the operator finds the `threescale-ca-bundle` ConfigMap, it reads CA certificates from the `ca-bundle.crt` key and uses them as trusted root CAs for all outbound TLS connections. If the ConfigMap is absent or the key is missing, the operator falls back to the system default CA pool.

## Creating the ConfigMap

### Single CA certificate

```bash
kubectl create configmap threescale-ca-bundle \
  --from-file=ca-bundle.crt=my-ca.crt \
  -n <operator-namespace>
```

### Multiple CA certificates (bundle)

Concatenate all PEM root certificates into a single file before creating the ConfigMap:

```bash
cat root-ca-1.crt root-ca-2.crt > ca-bundle.crt

kubectl create configmap threescale-ca-bundle \
  --from-file=ca-bundle.crt=ca-bundle.crt \
  -n <operator-namespace>
```

### OpenShift proxy CA injection (optional)

If your cluster uses a custom proxy CA and you need the operator to trust it, label an empty ConfigMap to have the cluster CA injection mechanism populate it with the merged proxy trust bundle:

```bash
kubectl create configmap threescale-ca-bundle -n <operator-namespace>
kubectl label configmap threescale-ca-bundle \
  config.openshift.io/inject-trusted-cabundle=true \
  -n <operator-namespace>
```

> **Note:** The injected bundle contains the proxy CA and system trusted CAs, but does **not** include the ingress router CA. If you need both, use [trust-manager](#combining-ca-sources-with-trust-manager) to combine the ingress CA with the proxy trust bundle.

## Combining CA sources with trust-manager

Use this section when you need to merge multiple CA sources into the `threescale-ca-bundle` ConfigMap — for example, the OpenShift cluster proxy CA together with a private CA used by a 3scale instance.

When the `config.openshift.io/inject-trusted-cabundle=true` label is set on the ConfigMap, the cluster CA injection mechanism takes ownership and replaces its contents on every update, preventing manual additions. [trust-manager](https://cert-manager.io/docs/trust/trust-manager/) solves this by merging multiple CA sources and writing the result to the target ConfigMap automatically.

### Prerequisites

Install cert-manager and trust-manager by following the [trust-manager installation guide](https://cert-manager.io/docs/trust/trust-manager/installation/).

### Step 1 — Create a ConfigMap for the cluster CA source

trust-manager reads Bundle sources from its trust namespace (`cert-manager` by default), so the injected ConfigMap must live there. Label a ConfigMap in the `cert-manager` namespace for OpenShift CA injection:

```bash
kubectl create configmap openshift-ca -n cert-manager
kubectl label configmap openshift-ca \
  config.openshift.io/inject-trusted-cabundle=true \
  -n cert-manager
```

### Step 2 — Create a ConfigMap or Secret for your custom CA

Place your custom CA in a separate ConfigMap (or Secret) also in the `cert-manager` namespace:

```bash
kubectl create configmap my-custom-ca \
  --from-file=ca.crt=my-custom-ca.crt \
  -n cert-manager
```

If your custom CA is already in a cert-manager-managed Secret, you can reference it directly as a `secret` source in the next step — no copy needed.

### Step 3 — Create a Bundle

Create a `Bundle` that merges both sources and writes the result to `threescale-ca-bundle` in the operator namespace:

```yaml
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: threescale-ca-bundle
spec:
  sources:
    - configMap:
        name: openshift-ca        # cluster CA injected in cert-manager namespace
        key: ca-bundle.crt
    - configMap:
        name: my-custom-ca        # your custom CA
        key: ca.crt
  target:
    configMap:
      key: ca-bundle.crt          # must match the key the operator reads
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: <operator-namespace>
```

For a cert-manager-managed Secret source, copy the CA certificate into a dedicated ConfigMap and reference that instead. See the trust-manager docs on [intentionally copying CA certificates](https://cert-manager.io/docs/trust/trust-manager/#cert-manager-integration-intentionally-copying-ca-certificates) for the recommended approach.

Apply it:

```bash
kubectl apply -f threescale-bundle.yaml
```

Verify it was written to the operator namespace:

```bash
kubectl get configmap threescale-ca-bundle -n <operator-namespace> \
  -o jsonpath='{.data.ca-bundle\.crt}' | openssl x509 -noout -subject -issuer
```

### Verifying the operator picked up the bundle

Check that the operator emitted no validation errors on the ConfigMap:

```bash
kubectl describe configmap threescale-ca-bundle -n <operator-namespace>
```

A successful load produces no `Warning` events. An invalid bundle shows an event similar to:

```
Warning  InvalidCABundle  <timestamp>  CABundleWatcher  InvalidCAFormat: no valid PEM-encoded certificates found in CA bundle
```

If you see this, verify the ConfigMap key contains well-formed PEM data (see [Verifying certificates with openssl](#verifying-certificates-with-openssl)).

### Example ConfigMap manifest

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: threescale-ca-bundle
  namespace: <operator-namespace>
data:
  ca-bundle.crt: |
    -----BEGIN CERTIFICATE-----
    <base64-encoded certificate data>
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    <base64-encoded certificate data>
    -----END CERTIFICATE-----
```

## Validation

The operator validates the contents of the `ca-bundle.crt` key when the ConfigMap is created or updated.

| Condition | Operator behaviour |
|---|---|
| ConfigMap absent | TLS uses system default CA pool; no error |
| `ca-bundle.crt` key absent | TLS uses system default CA pool; no error |
| Key present but empty | Error — `InvalidCAFormat`; `Warning` event emitted on the ConfigMap |
| Key contains no valid PEM CERTIFICATE blocks | Error — `InvalidCAFormat`; `Warning` event emitted on the ConfigMap |
| Key contains valid CERTIFICATE blocks plus other PEM block types (e.g. `PRIVATE KEY`) | Non-certificate blocks are silently skipped; certificates are loaded normally |
| Key contains one or more valid CERTIFICATE blocks | Success; TLS config updated immediately |

When validation fails, the operator emits a Kubernetes `Warning` event on the ConfigMap (reason: `InvalidCABundle`) and keeps the last known-good TLS configuration active. Inspect these events with:

```bash
kubectl describe configmap threescale-ca-bundle -n <operator-namespace>
```

## Reloading

The operator watches the `threescale-ca-bundle` ConfigMap for create, update, and delete events. Any change is picked up automatically — **no operator restart or annotation change is required**.

When the ConfigMap is deleted, the TLS configuration reverts to the system default CA pool immediately.

## Verifying certificates with openssl

### Inspect a single certificate

```bash
openssl x509 -in my-ca.crt -text -noout
```

This prints the subject, issuer, validity dates, and extensions of the certificate.

### Inspect all certificates in a bundle

```bash
awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' ca-bundle.crt \
  | awk 'BEGIN{n=0} /-----BEGIN CERTIFICATE-----/{n++; f="cert-"n".pem"} {print > f}'

for f in cert-*.pem; do
  echo "=== $f ==="
  openssl x509 -in "$f" -subject -issuer -dates -noout
done

rm -f cert-*.pem
```

### Verify the chain of trust

Check that a server certificate is signed by one of the CAs in the bundle:

```bash
openssl verify -CAfile ca-bundle.crt server.crt
```

Expected output:

```
server.crt: OK
```

### Test a live TLS connection using the bundle

```bash
openssl s_client -connect <host>:<port> -CAfile ca-bundle.crt -verify_return_error
```

A successful handshake shows `Verify return code: 0 (ok)` near the end of the output.

### Check certificate expiry dates across a bundle

```bash
openssl crl2pkcs7 -nocrl -certfile ca-bundle.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -A2 "subject"
```

Or using a loop:

```bash
while openssl x509 -noout -subject -dates 2>/dev/null; do :; done < ca-bundle.crt
```

### Generate a self-signed CA certificate for testing

```bash
openssl genrsa -out ca.key 2048

openssl req -x509 -new -nodes \
  -key ca.key \
  -sha256 \
  -days 365 \
  -out ca.crt \
  -subj "/CN=My Test CA"
```

The resulting `ca.crt` can be placed in the `ca-bundle.crt` key of the ConfigMap.
