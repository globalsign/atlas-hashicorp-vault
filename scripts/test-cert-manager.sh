#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
STARTING_DIR=`pwd`

# Defaults that are set when vault is running in dev mode.
export VAULT_ADDR='http://127.0.0.1:8200'
VAULT_TOKEN="root"

set -e

# Work from the  well known directory
cd "$DIR/.."

# Stop any currently running vaults
kill $(ps -a | grep vault | cut -d" " -f1) $(ps -a | grep vault | cut -d" " -f2) || echo ""

########### 1. Setup Vault ###########

echo "=== Starting Vault"
# Start the vault server locally
make > /dev/null 2>&1 &

# Artificial delay, to ensure that the vault server has bound to the port
sleep 5

echo "=== Verifying Vault"
# Check if vault is running and healthy
curl --retry 5 --retry-connrefused --fail $VAULT_ADDR/v1/sys/health

echo "=== Mounting Atlas Plugin"
# Mount the ATLAS Secret Plugin
vault secrets enable -options=OverrideDisableKeyUsageExtensions=true -options=OverrideDisableExtendedKeyUsageExtensions=true atlas 

echo "=== Logging Into Atlas"
# Use our login helper to authenticate using the plugin
"$DIR/login.sh"

echo "=== Creating a Vault Role for Cert Manager"
# Create A to use with cert manager
ROLE_NAME=my_certmanager_role
vault write atlas/roles/$ROLE_NAME allow_any_name=true enforce_hostnames=false

########### 1.2. Enable VM to talk to Local Vault (For Testing Only) ###########

# To handle enviormental diffrences, and to bypass network configuration nuance, we will use ngrok as a reverse proxy for vault.

echo "=== Exposing vault as a public endpiont for VM traffic"
# Install ngrok in tmp files
NGROK_ZIP=`tempfile`
NGROK=`tempfile`
curl https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip -o $NGROK_ZIP
unzip -p $NGROK_ZIP > $NGROK
chmod +x $NGROK

# Have ngrok binnary expose the vault port
$NGROK http `echo "$VAULT_ADDR" | cut -d: -f3` > /dev/null &
NGROCK_PID="$!"
sleep 5

# Get the Public URL of our vault instance using ngrok metadata API; We will use to enable vault and cert manager communication in section 3.
#
# NOTE: You can open http://127.0.0.1:4040 in your browser and inspect traffic to vault throigh ngrok proxy. This is useful for debugging.
PUBLIC_VAULT_URL=$(curl http://127.0.0.1:4040/api/tunnels | jq -r '.tunnels[] | select(.proto == "https") | .public_url')

########### 2. Setup MicroK8s (Local Kubernetes) ###########

# Install MicroK8s if its not installed
if ! command -v microk8s; then
    sudo snap install microk8s --classic --channel=1.18/stable
fi
KUBECTL=

echo "=== Starting MicroK8s"
# Ensure the cluster is started
microk8s start

# Enable some services, this tends to reduce issues with microk8s.
microk8s enable dns

# Quick Status Check.
microk8s status

########### 3. Install Cert Manager ###########

echo "=== Installing Cert Manager"
# Install Cert Manager
microk8s kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.1.0/cert-manager.yaml

# Verify Instalation
microk8s kubectl get pods --namespace cert-manager

echo "=== Waiting For Cert Manager pods to come online"
# We need to wait for cert manager to come online before we can create resources.
# Prime with 1 so we go through one check loop
not_ready_cnt=1
while [[ $not_ready_cnt != 0 ]]; do
    not_ready_cnt=0
    for s in $(microk8s kubectl get pods --namespace cert-manager -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}'); do
        if [[ "$s" == "False" ]]; then
            not_ready_cnt=$(($not_ready_cnt + 1))
        fi
    done
    sleep 0.5
done

# Wait for cert manager certs to propogate
echo "=== Waiting For Cert Manager Certificates to propogate (~30s)"
sleep 30

########### 3. Configure Cert Manager to work with Atlas Vault Plugin ###########

# Create a resources file that will configure cert manager to work with vault
EXAMPLE_CERT_NAME=atlas-demo-cert
EXAMPLE_CERT_SECRET_NAME=atlas-demo-tls-cert
RESOURCES_FILE=`tempfile`
cat > "$RESOURCES_FILE" <<-EOF
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager-demo
---
# This Secret Represents your Vault Token, This is one of many ways you can authenticate cert manager with vault.
# Refer to Cert Manager documentation for more info.
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  namespace: cert-manager-demo
  name: cert-manager-vault-token
data:
  # Kubernetes secrets are base 64 encoded
  # If you enter a non base64 encoded value you may see authentication errors in your event log.
  token: "$(echo "$VAULT_TOKEN" | base64)"
---
# The Issuer is responable for issuing certificates using an individual role.
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  namespace: cert-manager-demo
  # This is the name you will refrence in your certificate.
  name: my-globalsign-atlas
spec:
  vault:
    # Note that we are using the role we created in section 1.
    path: atlas/sign/${ROLE_NAME}

    # Note that we are using the public URL provided by Ngrok, in a production deployment this will be your vault cluster URL.
    server: ${PUBLIC_VAULT_URL}
    auth:
      # We are using token auth for this demo, but cert manager supports varoius authenticaition mechnisims.
      tokenSecretRef:
          name: cert-manager-vault-token
          key: token
---
# This is an example of a basic certificate using the above
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  namespace: cert-manager-demo
  # We are using a bash variable here so we can easaly retreive this value in section 4, and see the output cert.
  name: ${EXAMPLE_CERT_NAME}
spec:
  commonName: Hello Atlas
  # Secret name is used to refrence this value as a normal kubernetes secret, we will use this in section 4 to verify output
  secretName: ${EXAMPLE_CERT_SECRET_NAME}
  duration: 3h
  renewBefore: 2h
  issuerRef:
    # Note that we are using the name of the above issuer for this.
    name: my-globalsign-atlas
EOF

echo "=== Creating the following resources to link Cert Manager and Vault Atlas Plugin"
cat $RESOURCES_FILE

echo "=== Creating above resources now!"
microk8s kubectl apply -f $RESOURCES_FILE


echo "=== Waiting For Cert Manager to Issue Certs And Secrets (~30s)"
# Prime with 1 so we go through one check loop
not_ready_cnt=1
while [[ $not_ready_cnt != 0 ]]; do
    not_ready_cnt=0
    for s in $(microk8s kubectl get certificates ${EXAMPLE_CERT_NAME} --namespace cert-manager-demo -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}'); do
        if [[ "$s" == "False" ]]; then
            not_ready_cnt=$(($not_ready_cnt + 1))
        fi
    done
    sleep 1
done
# Extra time to reduce race conditions
sleep 120

########### 4. Check Output ###########


echo "=== Describing the created certificate"
microk8s kubectl describe certificates ${EXAMPLE_CERT_NAME} --namespace cert-manager-demo

echo "=== Describing the created secret"
microk8s kubectl describe secret ${EXAMPLE_CERT_SECRET_NAME} --namespace cert-manager-demo

echo "=== Rendering the Certificate with Open SSL"
microk8s kubectl get secret ${EXAMPLE_CERT_SECRET_NAME} --namespace cert-manager-demo -o 'jsonpath={.data}' | \
    jq -r '."tls.crt"' | base64 -d > tls.crt

cat tls.crt # & openssl x509 -in tls.crt -noout -text || echo ""


########### 5. Cleanup ###########

# Exit early if we were asked to keep it dirty.
if [[ "$1" == "dirty" ]]; then
    exit 0
fi

echo "=== Cleaning Up created Resources, If you would like to keep them next execution; run with the 'dirty' argument"

# Remove the resources we created
microk8s kubectl delete -f $RESOURCES_FILE
microk8s kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/v1.1.0/cert-manager.yaml

# Kill the vault instance we spawned, We cant get the PID as its a child process of make. As such we are searching for it.
#
# Kill the ngrok process we spawned, this will stop exposing our port.
kill $(ps -a | grep vault | cut -d" " -f1) $(ps -a | grep vault | cut -d" " -f2) $NGROCK_PID || echo ""

echo "NOTE: You may also want to run 'microk8s stop' if you want to stop your local cluster"
cd "$STARTING_DIR"
