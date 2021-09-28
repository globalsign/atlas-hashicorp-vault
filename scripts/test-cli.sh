DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
STARTING_DIR=`pwd`
export VAULT_ADDR='http://127.0.0.1:8200'

set -ex

if [[ "$OSTYPE" == "darwin"* ]]; then
  # Mac OSX
  TMP_JSON_OUT=`mktemp`
  TMP_CSR=`mktemp`
  TMP_PRIVATE_KEY=`mktemp`
else
  TMP_JSON_OUT=`tempfile`
  TMP_CSR=`tempfile`
  TMP_PRIVATE_KEY=`tempfile`
fi
# Start the vault server
cd "$DIR/.."
make > /dev/null 2>&1 &

# Artificial wait to ensure that the server has bound to the port
sleep 5

# Check if vault is running and healthy
curl --retry 5 --retry-connrefused --fail $VAULT_ADDR/v1/sys/health

# Mount the ATLAS Secret Plugin
vault secrets enable -options=OverrideDisableKeyUsageExtensions=true -options=OverrideDisableExtendedKeyUsageExtensions=true atlas

# Use our login helper to authenticate
"$DIR/login.sh"

# Create A Role.
vault write atlas/roles/demo_role allow_any_name=true enforce_hostnames=false

# Request Generation of a cert, using the example role
vault write -format json atlas/issue/demo_role alt_names="example.com" common_name="example_role" ext_key_usage="[]" ttl=1h > $TMP_JSON_OUT

# = Using the previously issued certificate's JSON, get the certificate
vault read atlas/cert/$(jq -r .data.serial_number $TMP_JSON_OUT | sed s/:/-/g)

# Read the CA Chain as JSON, parse the response, and view the certificate using openssl
vault read --format json atlas/cert/ca_chain | \
      jq -r .data.certificate | \
      openssl x509 -noout -text -in -

# Generate a CSR, Sign it using the Vault Atlas Plugin
# = Using Open SSL, Generate a new RSA Key and CSR with the provided subject
openssl req -nodes -newkey rsa:2048 -keyout $TMP_PRIVATE_KEY -out $TMP_CSR -subj "/CN=example_role2"

# = Using Vault sign the Generated CSR, save the output
vault write -format json atlas/sign/demo_role alt_names="example.com" common_name="example_role" csr="$(cat $TMP_CSR)" ttl=1h > $TMP_JSON_OUT

# = Using vault get the recently generated certifite using the returned serial number
vault read atlas/cert/$(jq -r .data.serial_number $TMP_JSON_OUT | sed s/:/-/g)

# = Using vault get the recently generated certifite using the returned serial number, extract the certificate and render it as text using openssl.
vault read --format json atlas/cert/$(jq -r .data.serial_number $TMP_JSON_OUT | sed s/:/-/g) | \
      jq -r .data.certificate | \
      openssl x509 -noout -text -in -

# Get a List of all certificates from vault, and revoke each one.
for sn in $(vault list -format json atlas/certs | jq -r .[] | cat)
do
     vault write atlas/revoke serial_number=${sn}
done

# Kill the Vault Server Process
kill $(ps -a | grep vault | cut -d" " -f 1) || echo ""
cd $STARTING_DIR
