package atlasvault

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathTidy(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy",
		Fields: map[string]*framework.FieldSchema{
			"tidy_cert_store": &framework.FieldSchema{
				Type: framework.TypeBool,
				Description: `Set to true to enable tidying up
the certificate store`,
			},

			"safety_buffer": &framework.FieldSchema{
				Type: framework.TypeDurationSecond,
				Description: `The amount of extra time that must have passed
beyond certificate expiration before it is removed
from the backend storage and Defaults to 72 hours.`,
				Default: 259200, //72h, but TypeDurationSecond currently requires defaults to be int
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathTidyWrite,
		},

		HelpSynopsis:    pathTidyHelpSyn,
		HelpDescription: pathTidyHelpDesc,
	}
}

func (b *Backend) pathTidyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// If we are a performance standby forward the request to the active node
	if b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) {
		return nil, logical.ErrReadOnly
	}

	safetyBuffer := d.Get("safety_buffer").(int)
	tidyCertStore := d.Get("tidy_cert_store").(bool)

	if safetyBuffer < 1 {
		return logical.ErrorResponse("safety_buffer must be greater than zero"), nil
	}

	bufferDuration := time.Duration(safetyBuffer) * time.Second

	if !atomic.CompareAndSwapUint32(b.tidyCASGuard, 0, 1) {
		resp := &logical.Response{}
		resp.AddWarning("Tidy operation already in progress.")
		return resp, nil
	}

	// Tests using framework will screw up the storage so make a locally
	// scoped req to hold a reference
	req = &logical.Request{
		Storage: req.Storage,
	}

	go func() {
		defer atomic.StoreUint32(b.tidyCASGuard, 0)

		// Don't cancel when the original client request goes away
		ctx = context.Background()

		logger := b.Logger().Named("tidy")

		doTidy := func() error {
			if tidyCertStore {
				serials, err := req.Storage.List(ctx, "certs/")
				if err != nil {
					return errwrap.Wrapf("error fetching list of certs: {{err}}", err)
				}

				for _, serial := range serials {
					certEntry, err := req.Storage.Get(ctx, "certs/"+serial)
					if err != nil {
						return errwrap.Wrapf(fmt.Sprintf("error fetching certificate %q: {{err}}", serial), err)
					}

					if certEntry == nil {
						logger.Warn("certificate entry is nil; tidying up since it is no longer useful for any server operations", "serial", serial)
						if err := req.Storage.Delete(ctx, "certs/"+serial); err != nil {
							return errwrap.Wrapf(fmt.Sprintf("error deleting nil entry with serial %s: {{err}}", serial), err)
						}
						continue
					}

					if certEntry.Value == nil || len(certEntry.Value) == 0 {
						logger.Warn("certificate entry has no value; tidying up since it is no longer useful for any server operations", "serial", serial)
						if err := req.Storage.Delete(ctx, "certs/"+serial); err != nil {
							return errwrap.Wrapf(fmt.Sprintf("error deleting entry with nil value with serial %s: {{err}}", serial), err)
						}
					}

					cert, err := x509.ParseCertificate(certEntry.Value)
					if err != nil {
						return errwrap.Wrapf(fmt.Sprintf("unable to parse stored certificate with serial %q: {{err}}", serial), err)
					}

					if time.Now().After(cert.NotAfter.Add(bufferDuration)) {
						if err := req.Storage.Delete(ctx, "certs/"+serial); err != nil {
							return errwrap.Wrapf(fmt.Sprintf("error deleting serial %q from storage: {{err}}", serial), err)
						}
					}
				}
			}

			return nil
		}

		if err := doTidy(); err != nil {
			logger.Error("error running tidy", "error", err)
			return
		}
	}()

	resp := &logical.Response{}
	resp.AddWarning("Tidy operation successfully started. Any information from the operation will be printed to Vault's server logs.")
	return logical.RespondWithStatusCode(resp, req, http.StatusAccepted)
}

const pathTidyHelpSyn = `
Tidy up the backend by removing expired certificates.
`

const pathTidyHelpDesc = `
This endpoint allows expired certificates to be removed from the backend, freeing up storage.
For safety, this function is a noop if called without parameters; cleanup from normal 
certificate storage must be enabled with 'tidy_cert_store'. All certificates and currently
stored in the backend will be checked when this endpoint is hit. The expiration of the 
certificate of each certificate being held in certificate storage will then be checked. 
If the current time, minus the value of 'safety_buffer', is greater than the expiration, 
it will be removed.
`
