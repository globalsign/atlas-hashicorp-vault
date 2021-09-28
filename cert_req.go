package atlasvault

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
)

// ATLAS Cert request is everything needed to translate a PKI request to atlas
type atlasCertRequest struct {
	CSR          []byte
	CertTemplate *x509.Certificate
	PrivateKey   *privKey
}

type privKey struct {
	Signer crypto.Signer
	Type   certutil.PrivateKeyType
	Bytes  []byte
}

func (hcr *atlasCertRequest) SetParsedPrivateKey(s crypto.Signer, t certutil.PrivateKeyType, r []byte) {
	hcr.PrivateKey = &privKey{Signer: s, Type: t, Bytes: r}
}

func (hcr *atlasCertRequest) GenerateCSR(data *dataBundle) error {
	var err error
	if err := hcr.PopulateCertTemplate(data); err != nil {
		return err
	}

	if err := hcr.GeneratePrivateKey(data); err != nil {
		return err
	}

	csrTemplate := &x509.CertificateRequest{
		Subject:        data.params.Subject,
		DNSNames:       data.params.DNSNames,
		EmailAddresses: data.params.EmailAddresses,
		IPAddresses:    data.params.IPAddresses,
		URIs:           data.params.URIs,
	}
	if err := handleOtherCSRSANs(csrTemplate, data.params.OtherSANs); err != nil {
		return errutil.InternalError{Err: errwrap.Wrapf("error marshaling other SANs: {{err}}", err).Error()}
	}

	// CSR Is CSR bytes to be sent
	hcr.CSR, err = x509.CreateCertificateRequest(rand.Reader, csrTemplate, hcr.PrivateKey.Signer)
	if err != nil {
		return errutil.InternalError{Err: fmt.Sprintf("unable to create certificate: %s", err)}
	}

	return nil
}

func (hcr *atlasCertRequest) PopulateCertTemplate(data *dataBundle) error {
	hcr.CertTemplate = &x509.Certificate{
		// Set by ATLAS
		// SerialNumber:   serialNumber,
		NotBefore: time.Now().Add(-30 * time.Second),
		NotAfter:  data.params.NotAfter,
		IsCA:      false,
		// Set by generate private key
		// SubjectKeyId:   subjKeyID,
		Subject:        data.params.Subject,
		DNSNames:       data.params.DNSNames,
		EmailAddresses: data.params.EmailAddresses,
		IPAddresses:    data.params.IPAddresses,
		URIs:           data.params.URIs,
	}
	addPolicyIdentifiers(data, hcr.CertTemplate)
	addKeyUsages(data, hcr.CertTemplate)
	addExtKeyUsageOids(data, hcr.CertTemplate)

	// This will only be filled in from the generation paths
	if len(data.params.PermittedDNSDomains) > 0 {
		hcr.CertTemplate.PermittedDNSDomains = data.params.PermittedDNSDomains
		hcr.CertTemplate.PermittedDNSDomainsCritical = true
	}
	return nil
}

func (hcr *atlasCertRequest) GeneratePrivateKey(data *dataBundle) error {
	var err error
	if err := certutil.GeneratePrivateKey(data.params.KeyType, data.params.KeyBits, hcr); err != nil {
		return err
	}

	hcr.CertTemplate.SubjectKeyId, err = certutil.GetSubjKeyID(hcr.PrivateKey.Signer)
	if err != nil {
		return errutil.InternalError{Err: fmt.Sprintf("error getting subject key ID: %s", err)}
	}

	return nil
}
