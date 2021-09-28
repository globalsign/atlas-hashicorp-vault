package atlasvault

import (
	"context"
	"crypto/tls"
	"encoding/base64"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// configAPIKey is the plugin storage path component for the Atlas API key, used under the system prefix
	configAPIKey = "api_key"
	// configAPISecret is the plugin storage path component for the Atlas API secret, used under the system prefix
	configAPISecret = "api_secret"
	// configAPIKey is the plugin storage path component for the Atlas Client Certificate, used under the system prefix, storing a combined Cert and Key Blob in PEM format.
	configAPICertifcate = "api_cert"
	// configAPIKey is the plugin storage path component for the Atlas Client Certificate Private Key, used under the system prefix
	configAPICertifcateKey = "api_cert_key"
)

func pathConfigureAuthn(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/authn",
		Fields: map[string]*framework.FieldSchema{
			configAPIKey: &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `The ATLAS API Key you wish to use.`,
			},
			configAPISecret: &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `The ATLAS API Secret you wish to use.`,
			},

			configAPICertifcate: &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `The ATLAS Base64 encoded PEM formated client certificate to use when authenticating with ATLAS.`,
			},
			configAPICertifcateKey: &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `The base64 encoded PEM formatted private key associated with the client certificate.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.handleConfigWrite,
		},

		HelpSynopsis:    `Configures the ATLAS backend authentication information..`,
		HelpDescription: `Sets the API and mTLS credentials for authenticating with GlobalSign ATLAS.`,
	}
}

func (b *Backend) handleConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, errutil.UserError{Err: "client token must not be empty"}
	}

	// Check to make sure that kv pairs provided
	if len(req.Data) == 0 {
		return nil, errutil.UserError{Err: "data must be provided to store in secret"}
	}

	apiKey, ok := data.Get(configAPIKey).(string)
	if ok && apiKey != "" {
		err := b.setSystemValue(ctx, req.Storage, storageAtlasAPIKey, []byte(apiKey))
		if err != nil {
			return nil, errutil.InternalError{Err: "Failed to Save api_key: " + err.Error()}
		}
	}

	apiSecret, ok := data.Get(configAPISecret).(string)
	if ok && apiSecret != "" {
		err := b.setSystemValue(ctx, req.Storage, storageAtlasAPISecret, []byte(apiSecret))

		if err != nil {
			return nil, errutil.InternalError{Err: "Failed to Save api_secret: " + err.Error()}
		}
	}

	apiCert, okCert := data.Get(configAPICertifcate).(string)
	apiCertKey, okKey := data.Get(configAPICertifcateKey).(string)
	if okCert && !okKey {
		return nil, errutil.UserError{Err: "Must Provide Certificate and Private Key together"}
	}
	if apiCert != "" {
		// Value needs to be storable in a UTF8 string, we chose base64 as it tends to be more readably available across languages.
		certPem, err := base64.StdEncoding.DecodeString(apiCert)
		if err != nil {
			return nil, errutil.UserError{Err: "Client Certificate Must be Base64 Encoded (Std): " + err.Error()}
		}
		keyPem, err := base64.StdEncoding.DecodeString(apiCertKey)
		if err != nil {
			return nil, errutil.UserError{Err: "Client Certificate Key Must be Base64 Encoded (Std): " + err.Error()}
		}

		// Parse to validate input will work for future calls.
		_, err = tls.X509KeyPair([]byte(certPem), []byte(keyPem))
		if err != nil {
			return nil, errutil.UserError{Err: "Failed to parse mTLS Keypair: " + err.Error()}
		}

		err = b.setSystemValue(ctx, req.Storage, storageAtlasAPICert, append([]byte(certPem), append([]byte("\n"), []byte(keyPem)...)...))
		if err != nil {
			return nil, errutil.InternalError{Err: "Failed to persist Client MTLS Keypair: " + err.Error()}
		}
	}

	client, err := b.GetAtlasClient(ctx, req.Storage)
	if err != nil {
		return nil, errutil.InternalError{Err: "atlas client retrieval: " + err.Error()}
	}

	// Make a request to test the connection
	_, err = client.GetConfig(ctx)
	if err != nil {
		return nil, errutil.InternalError{Err: "atlas test request failed: " + err.Error()}
	}

	return nil, nil
}
