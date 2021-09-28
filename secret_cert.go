package atlasvault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// secretCertsType is the name used to identify this type
const secretCertsType = "atlas-pki"

func secretCerts(b *Backend) *framework.Secret {
	return &framework.Secret{
		Type: secretCertsType,
		Fields: map[string]*framework.FieldSchema{
			"certificate": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The PEM-encoded concatenated certificate and
issuing certificate authority`,
			},
			"private_key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The PEM-encoded private key for the certificate",
			},
			"serial": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The serial number of the certificate, for handy
reference`,
			},
		},

		Revoke: b.secretCredsRevoke,
	}
}

func (b *Backend) secretCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Secret == nil {
		return nil, fmt.Errorf("secret is nil in request")
	}

	serialInt, ok := req.Secret.InternalData["serial_number"]
	if !ok {
		return nil, fmt.Errorf("could not find serial in internal secret data")
	}

	return revokeCert(ctx, b, req, serialInt.(string), true)
}
