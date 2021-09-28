#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

CREDS_DIR="$DIR/../.private/dev-creds"

taint=0

echo "=== Please Provide you Globalsign Atlas Credentials ==="
if [[ -f "$CREDS_DIR/api.json" ]]; then
     echo "Loading API Credentials From File"
     api_key=`jq -r .user.api_key "$CREDS_DIR/api.json"`
     api_secret=`jq -r .user.api_secret "$CREDS_DIR/api.json"`
else
     read -p  'API Key: ' api_key
     read -sp 'API Secret: [Secure Entry]' api_secret
     echo ""
     taint=1
fi

if [[ -f "$CREDS_DIR/cert.pem" ]]; then
     echo "Loading API Cert From File"
     api_cert_file="$CREDS_DIR/cert.pem"
else
     read -p 'API Client Certificate File (PEM): '  api_cert_file
     echo ""
     taint=1
fi


if [[ -f "$CREDS_DIR/key.pem" ]]; then
     echo "Loading API Cert Key From File"
     api_cert_key_file="$CREDS_DIR/key.pem"
else
     read -p 'API Client Certificate Key File (PEM): '  api_cert_key_file
     echo ""
     taint=1
fi

# If we had manual user input ask if we should persist to disk
if [[ $taint -eq 1 ]]; then
     echo "Proposed Dev Credential Directory: '$CREDS_DIR/'"
     read -p 'Would you like to persist these as dev Credentals (y/n):'  should_persist
     if [[ $should_persist -eq y ]]; then 
          mkdir -p "$CREDS_DIR"
          chmod 700 "$CREDS_DIR"
          cp "$api_cert_file" "$CREDS_DIR/cert.pem"
          cp "$api_cert_key_file" "$CREDS_DIR/key.pem"
          cat > "$CREDS_DIR/api.json" <<EOF
{ "user": { "api_key": "$api_key", "api_secret": "$api_secret" }}
EOF
          echo "== Persisted dev credentials!"
     fi
fi

# If the next commands fail we want to abort, let bash know by setting the -e flag
set -e 

# Copy the Client Certificate into the Private directory
vault write atlas/config/authn \
     api_key="$api_key" \
     api_secret="$api_secret" \
     api_cert="$(base64 < "$api_cert_file")" \
     api_cert_key="$(base64 < "$api_cert_key_file")"

echo "== Successfully Authenticated!"