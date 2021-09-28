# Using Atlas Secret engine with Cert Manager on MicroK8s

For a working demo refer to [scripts/test-cert-manager.sh](https://github.com/globalsign/atlas-hashicorp-vault/blob/master/scripts/test-cert-manager.sh)

[![asciicast](https://asciinema.org/a/BvSo8Hw1vTjBVaOmLeUp78XEb.svg)](https://asciinema.org/a/BvSo8Hw1vTjBVaOmLeUp78XEb)

## Manually Setting Up Cert Manager

1. Start and Configure Vault

```sh
# Create a configuration file so vault knows where to load plugins from
cat > vault-config.hcl <<EOF
plugin-folder="./vault"
EOF

# Create the plugin directory
mkdir -p ./vault

# Download the latest release
wget <RELEASE_URL> -o ./vault/atlas

# Download the plugin into the desired destination folder
vault server -dev
export VAULT_ADDR='http://127.0.0.1:8200'

# Start Vault API server
vault > vault.log &

# Mount the plugin
vault secrets enable atlas

# Authenticate the Plugin
vault write atlas/config/authn < ./my-credentials.json

# Create a Role to issue certs with
vault write atlas/roles/demo_role allow_any_name=true enforce_hostnames=false
```

1. Install MicroK8s on your platform: https://microk8s.io/docs

Install docker machiene, this is needed for MicroK8s

Install MicroK8s you can do this in ubuntu with:  `sudo snap install microk8s --classic --channel=1.18/stable`


2. Start Your MicroK8s

```sh
microk8s start
```

3. Install Cert Manager into your microk8s cluster

```sh
microk8s kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.1.0/cert-manager.yaml

# Verify Installation of Cert-Manager
microk8s kubectl get pods --namespace cert-manager
```

4. Configure Cert-Manager to issue cretificates using vault.

Applying the below will, enable cert manager to issue using your atlas instance.

> Note: The below assumes you mounted the atlas plugin at its default location.
```sh
cat <<EOF > test-resources.yaml
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: cert-manager-vault-token
  namespace: cert-manager-test
data:
  token: "<YourVaultToken>"
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: globalsign-atlas
  namespace: cert-manager-test
spec:
  vault:
    path: atlas/sign/demo_role
    server: https://myvault.local
    caBundle: <base64 encoded caBundle PEM file>
    auth:
      tokenSecretRef:
          name: cert-manager-vault-token
          key: token
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: atlas-cert
  namespace: cert-manager-test
spec:
  dnsNames:
    - example.com
  secretName: atlas-cert-tls
  issuerRef:
    name: globalsign-atlas
EOF

# Create the namespace
microk8s kubectl create namespace cert-manager-test
microk8s kubectl apply -f test-resources.yaml
```
