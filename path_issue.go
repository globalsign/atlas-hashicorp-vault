package atlasvault

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// Derived from: https://github.com/hashicorp/vault/blob/df18871704fe869e9be45b542a6b1eb2fe46c293/builtin/logical/pki/path_issue_sign.go

func pathIssue(b *Backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "issue/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathIssue,
		},

		HelpSynopsis:    pathIssueHelpSyn,
		HelpDescription: pathIssueHelpDesc,
	}

	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})
	return ret
}

func pathSign(b *Backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathSign,
		},

		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}

	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})

	ret.Fields["csr"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: `PEM-format CSR to be signed.`,
	}

	return ret
}

// pathIssue issues a certificate and private key from given parameters,
// subject to role restrictions
func (b *Backend) pathIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)

	// Get the role
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
	}

	if role.KeyType == "any" {
		return logical.ErrorResponse("role key type \"any\" not allowed for issuing certificates, only signing"), nil
	}

	return b.pathIssueSignCert(ctx, req, data, role, false, false)
}

// pathSign issues a certificate from a submitted CSR, subject to role
// restrictions
func (b *Backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)

	// Get the role
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
	}

	return b.pathIssueSignCert(ctx, req, data, role, true, false)
}

func (b *Backend) pathIssueSignCert(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry, useCSR, useCSRValues bool) (*logical.Response, error) {
	format := getFormat(data)
	if format == "" {
		return logical.ErrorResponse(
			`the "format" path parameter must be "pem", "der", or "pem_bundle"`), nil
	}

	input := &dataBundle{
		req:     req,
		apiData: data,
		role:    role,
	}
	var parsedBundle *certutil.ParsedCertBundle
	var err error

	client, err := b.GetAtlasClient(ctx, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("atlas client retrieval: {{err}}", err)

	}

	if useCSR {
		// CSR is at
		csrString := data.Get("csr").(string)
		if csrString == "" {
			return nil, errutil.UserError{Err: fmt.Sprintf("\"csr\" is empty")}
		}

		parsedBundle, err = signCert(ctx, b, input, false, useCSRValues, client)
	} else {
		parsedBundle, err = generateCert(ctx, b, input, false, client)
	}

	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		case errutil.InternalError:
			return nil, err
		}
	}

	// Produce the certificate bundle
	cb, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, errwrap.Wrapf("error converting raw cert bundle to cert bundle: {{err}}", err)
	}

	// Formulate a response?
	respData := map[string]interface{}{
		"serial_number": cb.SerialNumber,
	}

	// Based on format produce output
	switch format {
	case "pem":
		// respData["issuing_ca"] = signingCB.Certificate
		respData["certificate"] = cb.Certificate
		if cb.CAChain != nil && len(cb.CAChain) > 0 {
			respData["ca_chain"] = cb.CAChain
		}
		if !useCSR {
			respData["private_key"] = cb.PrivateKey
			respData["private_key_type"] = cb.PrivateKeyType
		}

	case "pem_bundle":
		// respData["issuing_ca"] = signingCB.Certificate
		respData["certificate"] = cb.ToPEMBundle()
		if cb.CAChain != nil && len(cb.CAChain) > 0 {
			respData["ca_chain"] = cb.CAChain
		}
		if !useCSR {
			respData["private_key"] = cb.PrivateKey
			respData["private_key_type"] = cb.PrivateKeyType
		}

	case "der":
		respData["certificate"] = base64.StdEncoding.EncodeToString(parsedBundle.CertificateBytes)
		// respData["issuing_ca"] = base64.StdEncoding.EncodeToString(signingBundle.CertificateBytes)

		var caChain []string
		for _, caCert := range parsedBundle.CAChain {
			caChain = append(caChain, base64.StdEncoding.EncodeToString(caCert.Bytes))
		}
		if caChain != nil && len(caChain) > 0 {
			respData["ca_chain"] = caChain
		}

		if !useCSR {
			respData["private_key"] = base64.StdEncoding.EncodeToString(parsedBundle.PrivateKeyBytes)
			respData["private_key_type"] = cb.PrivateKeyType
		}
	}

	var resp *logical.Response
	switch {
	case role.GenerateLease == nil:
		return nil, fmt.Errorf("generate lease in role is nil")
	case *role.GenerateLease == false:
		// If lease generation is disabled do not populate `Secret` field in
		// the response
		resp = &logical.Response{
			Data: respData,
		}
	default:
		resp = b.Secret(secretCertsType).Response(
			respData,
			map[string]interface{}{
				"serial_number": cb.SerialNumber,
			})
		resp.Secret.TTL = parsedBundle.Certificate.NotAfter.Sub(time.Now())
	}

	if data.Get("private_key_format").(string) == "pkcs8" {
		err = convertRespToPKCS8(resp)
		if err != nil {
			return nil, err
		}
	}

	if !role.NoStore {
		err = req.Storage.Put(ctx, &logical.StorageEntry{
			Key:   "certs/" + normalizeSerial(cb.SerialNumber),
			Value: parsedBundle.CertificateBytes,
		})
		if err != nil {
			return nil, errwrap.Wrapf("unable to store certificate locally: {{err}}", err)
		}
	}

	if useCSR {
		if role.UseCSRCommonName && data.Get("common_name").(string) != "" {
			resp.AddWarning("the common_name field was provided but the role is set with \"use_csr_common_name\" set to true")
		}
		if role.UseCSRSANs && data.Get("alt_names").(string) != "" {
			resp.AddWarning("the alt_names field was provided but the role is set with \"use_csr_sans\" set to true")
		}
	}

	return resp, nil
}

const pathIssueHelpSyn = `
Request a certificate using a certain role with the provided details.
`

const pathIssueHelpDesc = `
This path allows requesting a certificate to be issued according to the
policy of the given role. The certificate will only be issued if the
requested details are allowed by the role policy.
This path returns a certificate and a private key. If you want a workflow
that does not expose a private key, generate a CSR locally and use the
sign path instead.
`

const pathSignHelpSyn = `
Request certificates using a certain role with the provided details.
`

const pathSignHelpDesc = `
This path allows requesting certificates to be issued according to the
policy of the given role. The certificate will only be issued if the
requested common name is allowed by the role policy.
This path requires a CSR; if you want Vault to generate a private key
for you, use the issue path instead.
`
