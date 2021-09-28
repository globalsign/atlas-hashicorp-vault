package atlasvault

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRevoke(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: `revoke`,
		Fields: map[string]*framework.FieldSchema{
			"serial_number": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `Certificate serial number, in colon- or
hyphen-separated octal`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRevokeWrite,
		},

		HelpSynopsis:    pathRevokeHelpSyn,
		HelpDescription: pathRevokeHelpDesc,
	}
}

func (b *Backend) pathRevokeWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serial := data.Get("serial_number").(string)
	if len(serial) == 0 {
		return logical.ErrorResponse("The serial number must be provided"), nil
	}

	// We store and identify by lowercase colon-separated hex, but other
	// utilities use dashes and/or uppercase, so normalize
	serial = strings.Replace(strings.ToLower(serial), "-", ":", -1)

	return revokeCert(ctx, b, req, serial, false)
}

type revocationInfo struct {
	CertificateBytes  []byte    `json:"certificate_bytes"`
	RevocationTime    int64     `json:"revocation_time"`
	RevocationTimeUTC time.Time `json:"revocation_time_utc"`
}

// Revokes a cert, and tries to be smart about error recovery
func revokeCert(ctx context.Context, b *Backend, req *logical.Request, serial string, fromLease bool) (*logical.Response, error) {
	atlas, err := b.GetAtlasClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	alreadyRevoked := false
	var revInfo revocationInfo

	// 1. Check the local status of a certificate
	revEntry, err := fetchCertBySerial(ctx, req, "revoked/", serial)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		case errutil.InternalError:
			return nil, err
		}
	}

	// 2. If we were able to find a certifcate and parse it, check if the value was locally reported as revoked.
	if revEntry != nil {
		// Set the revocation info to the existing values
		alreadyRevoked = true
		err = revEntry.DecodeJSON(&revInfo)
		if err != nil {
			return nil, fmt.Errorf("error decoding existing revocation info")
		}
	}

	// 3. Request revocation from atlas, note we are relying on the service's impotency.
	rawHex := strings.Replace(strings.Replace(strings.ToLower(serial), "-", "", -1), ":", "", -1)
	crlErr := atlas.RevokeCert(ctx, rawHex)
	switch crlErr.(type) {
	case errutil.UserError:
		return logical.ErrorResponse(fmt.Sprintf("error during revocation: %s", crlErr)), nil
	case errutil.InternalError:
		return nil, errwrap.Wrapf("error encountered during revocation: {{err}}", crlErr)
	}

	// 4. If we are not revoked, revoke it locally.
	if !alreadyRevoked {
		certEntry, err := fetchCertBySerial(ctx, req, "certs/", serial)
		if err != nil {
			switch err.(type) {
			case errutil.UserError:
				return logical.ErrorResponse(err.Error()), nil
			case errutil.InternalError:
				return nil, err
			}
		}
		if certEntry == nil {
			if fromLease {
				// We can't write to revoked/ or update the CRL anyway because we don't have the cert,
				// and there's no reason to expect this will work on a subsequent
				// retry.  Just give up and let the lease get deleted.
				b.Logger().Warn("expired certificate revoke failed because not found in storage, treating as success", "serial", serial)
				return nil, nil
			}
			return logical.ErrorResponse(fmt.Sprintf("certificate with serial %s not found", serial)), nil
		}

		cert, err := x509.ParseCertificate(certEntry.Value)
		if err != nil {
			return nil, errwrap.Wrapf("error parsing certificate: {{err}}", err)
		}
		if cert == nil {
			return nil, fmt.Errorf("got a nil certificate")
		}

		// Add a little wiggle room because leases are stored with a second
		// granularity
		if cert.NotAfter.Before(time.Now().Add(2 * time.Second)) {
			return nil, nil
		}

		currTime := time.Now()
		revInfo.CertificateBytes = certEntry.Value
		revInfo.RevocationTime = currTime.Unix()
		revInfo.RevocationTimeUTC = currTime.UTC()

		revEntry, err = logical.StorageEntryJSON("revoked/"+normalizeSerial(serial), revInfo)
		if err != nil {
			return nil, fmt.Errorf("error creating revocation entry")
		}

		err = req.Storage.Put(ctx, revEntry)
		if err != nil {
			return nil, fmt.Errorf("error saving revoked certificate to new location")
		}

	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"revocation_time": revInfo.RevocationTime,
		},
	}
	if !revInfo.RevocationTimeUTC.IsZero() {
		resp.Data["revocation_time_rfc3339"] = revInfo.RevocationTimeUTC.Format(time.RFC3339Nano)
	}
	return resp, nil
}

const pathRevokeHelpSyn = `
Revoke a certificate by serial number.
`

const pathRevokeHelpDesc = `
This allows certificates to be revoked using its serial number. A root token is required.
`
