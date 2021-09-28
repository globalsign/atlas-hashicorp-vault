package atlas

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/url"
)

type (

	// IssueCertRequest is the base structure for certificate requests
	IssueCertRequest struct {
		Validity            *Validity            `json:"validity,omitempty" validate:"required"`
		SubjectDN           *SubjectDN           `json:"subject_dn,omitempty" validate:"required"`
		SAN                 *SAN                 `json:"san,omitempty"`
		SubjectDA           *SubjectDA           `json:"subject_da,omitempty"`
		KeyUsages           *KeyUsages           `json:"key_usages,omitempty"`
		ExtendedKeyUsages   []string             `json:"extended_key_usages,omitempty"`
		QualifiedStatements *QualifiedStatements `json:"qualified_statements,omitempty"`
		MsExtensionTemplate *MsExtensionTemplate `json:"ms_extension_template,omitempty"`
		CustomExtensions    map[string]string    `json:"custom_extensions,omitempty"`
		Signature           *Signature           `json:"signature,omitempty"`
		PublicKey           string               `json:"public_key" validate:"required"`
		PublicKeySignature  string               `json:"public_key_signature,omitempty"`
	}

	// Validity represents the valid time range for the Certificate request
	Validity struct {
		NotBefore int64 `json:"not_before" validate:"required"`
		NotAfter  int64 `json:"not_after,omitempty"`
	}

	// SubjectDnExtraAttribute represents Extra Subject DN Attributes within a Certificate Request
	SubjectDnExtraAttribute struct {
		Type  string `json:"type" validate:"required"`
		Value string `json:"value"`
	}

	// SubjectDN represents the certificate SubjectDN within the Certificate request.
	SubjectDN struct {
		CommonName                                     string                     `json:"common_name,omitempty"`
		Country                                        string                     `json:"country,omitempty"`
		State                                          string                     `json:"state,omitempty"`
		Locality                                       string                     `json:"locality,omitempty"`
		StreetAddress                                  string                     `json:"street_address,omitempty"`
		Organization                                   string                     `json:"organization,omitempty"`
		OrganizationalUnit                             []string                   `json:"organizational_unit,omitempty"`
		Email                                          string                     `json:"email,omitempty"`
		JurisdictionOfIncorporationLocalityName        string                     `json:"jurisdiction_of_incorporation_locality_name,omitempty"`
		JurisdictionOfIncorporationStateOrProvinceName string                     `json:"jurisdiction_of_incorporation_state_or_province_name,omitempty"`
		JurisdictionOfIncorporationCountryName         string                     `json:"jurisdiction_of_incorporation_country_name,omitempty"`
		BusinessCategory                               string                     `json:"business_category,omitempty"`
		ExtraAttributes                                []*SubjectDnExtraAttribute `json:"extra_attributes,omitempty"`
	}

	// SANOtherNames represents subject alternative names: other names in the certificate request.
	SANOtherNames struct {
		Type  string `json:"type"`
		Value string `json:"value,omitempty"`
	}

	// SAN represents Subject Alternative Names in a certificate request.
	SAN struct {
		DNSNames    []string         `json:"dns_names,omitempty"`
		IPAddresses []string         `json:"ip_addresses,omitempty"`
		URIs        []string         `json:"uris,omitempty"`
		Emails      []string         `json:"emails,omitempty"`
		OtherNames  []*SANOtherNames `json:"other_names,omitempty"`
	}

	// SubjectDaExtraAttribute is used for defining Extra SubjectDA within a certifcate request
	SubjectDaExtraAttribute struct {
		Type  string `json:"type"`
		Value string `json:"value,omitempty"`
	}

	// SubjectDA is used to define SubjectDA within a certificate request.
	SubjectDA struct {
		Gender               string                     `json:"gender,omitempty"`
		DateOfBirth          string                     `json:"date_of_birth,omitempty"`
		PlaceOfBirth         string                     `json:"place_of_birth,omitempty"`
		CountryOfCitizenship []string                   `json:"country_of_citizenship,omitempty"`
		CountryOfResidence   []string                   `json:"country_of_residence,omitempty"`
		ExtraAttributes      []*SubjectDaExtraAttribute `json:"extra_attributes,omitempty"`
	}

	// KeyUsages defines how a certificate can be used within a certifcate request.
	KeyUsages struct {
		DigitalSignature   *bool `json:"digital_signature,omitempty"`
		ContentCommitment  *bool `json:"content_commitment,omitempty"`
		KeyEncipherment    *bool `json:"key_encipherment,omitempty"`
		DataEncipherment   *bool `json:"data_encipherment,omitempty"`
		KeyAgreement       *bool `json:"key_agreement,omitempty"`
		KeyCertificateSign *bool `json:"key_certificate_sign,omitempty"`
		CrlSign            *bool `json:"crl_sign,omitempty"`
		EncipherOnly       *bool `json:"encipher_only,omitempty"`
		DecipherOnly       *bool `json:"decipher_only,omitempty"`
	}

	QualifiedStatementsSemantics struct {
		Identifier      string   `json:"identifier,omitempty"`
		NameAuthorities []string `json:"name_authorities,omitempty"`
	}
	QualifiedStatements struct {
		Semantics             *QualifiedStatementsSemantics `json:"semantics,omitempty"`
		EtsiQcCompliance      bool                          `json:"etsi_qc_compliance,omitempty"`
		EtsiQcType            string                        `json:"etsi_qc_type,omitempty"`
		EtsiQcSscdCompliance  bool                          `json:"etsi_qc_sscd_compliance,omitempty"`
		EtsiQcRetentionPeriod int                           `json:"etsi_qc_retention_period,omitempty"`
		EtsiQcPds             map[string]string             `json:"etsi_qc_pds,omitempty"`
	}

	MsExtensionTemplate struct {
		ID           string `json:"id,omitempty"`
		MajorVersion int    `json:"major_version,omitempty"`
		MinorVersion int    `json:"minor_version,omitempty"`
	}

	// Signature represents the parameters used for generating the CSR within a Certificate Request
	Signature struct {
		Algorithm     string `json:"algorithm,omitempty"`
		HashAlgorithm string `json:"hash_algorithm,omitempty"`
	}

	// CertRequestOptions dictates overrides and options when generating a cert request object from a template
	CertRequestOptions struct {
		// OverrideSignatureAlgorithm will explicitly set the signature algorithm
		OverrideSignatureAlgorithm *string

		// OverrideSignatureHashAlgorithm will explicitly set the hash algorithm
		OverrideSignatureHashAlgorithm *string

		// OverrideHasStaticKeyUsage will omit key usage information to handle static key usage policy
		OverrideDisableKeyUsageExtensions bool

		// OverrideHasStaticKeyUsage will omit key usage information to handle static key usage policy
		OverrideDisableExtendedKeyUsageExtensions bool
	}
)

// newBool Functions to convert bool to *bool
func newBool(nonPointer bool) *bool {
	b := nonPointer
	return &b
}

// NewIssueCertRequest calculates an Atlas Certificate request payload based on a CSR and x509 certificate acting as a template.
func NewIssueCertRequest(csr []byte, certTemplate *x509.Certificate, opts *CertRequestOptions) (*IssueCertRequest, error) {
	csrPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

	req := &IssueCertRequest{
		Validity: &Validity{
			// Required, So set this first
			NotBefore: certTemplate.NotBefore.Unix(),
			// Zero should be omitted
			NotAfter: certTemplate.NotAfter.Unix(),
		},
		SubjectDN: NewSubjectDN(&certTemplate.Subject),
		SAN: &SAN{
			DNSNames:    certTemplate.DNSNames,
			IPAddresses: marshalIPs(certTemplate.IPAddresses),
			URIs:        marshalURIs(certTemplate.URIs),
			Emails:      certTemplate.EmailAddresses,
		},
		ExtendedKeyUsages: append(marshalExtendedKeyUsage(certTemplate.ExtKeyUsage), asn1OIDStr(certTemplate.UnknownExtKeyUsage)...),
		KeyUsages: &KeyUsages{
			DigitalSignature:   newBool(certTemplate.KeyUsage&x509.KeyUsageDigitalSignature != 0),
			ContentCommitment:  newBool(certTemplate.KeyUsage&x509.KeyUsageContentCommitment != 0),
			KeyEncipherment:    newBool(certTemplate.KeyUsage&x509.KeyUsageKeyEncipherment != 0),
			DataEncipherment:   newBool(certTemplate.KeyUsage&x509.KeyUsageDataEncipherment != 0),
			KeyAgreement:       newBool(certTemplate.KeyUsage&x509.KeyUsageKeyAgreement != 0),
			KeyCertificateSign: newBool(certTemplate.KeyUsage&x509.KeyUsageCertSign != 0),
			CrlSign:            newBool(certTemplate.KeyUsage&x509.KeyUsageCRLSign != 0),
			EncipherOnly:       newBool(certTemplate.KeyUsage&x509.KeyUsageEncipherOnly != 0),
			DecipherOnly:       newBool(certTemplate.KeyUsage&x509.KeyUsageDecipherOnly != 0),
		},
		Signature: &Signature{
			// These hard coded algorithms are the defaults of the system, they can be overridden using the options object.
			HashAlgorithm: "SHA-256",
		},
		PublicKey: string(csrPem),
	}

	// Handle Options
	if opts != nil {
		// Override with zero key usages object to handle static case
		if opts.OverrideDisableKeyUsageExtensions {
			req.KeyUsages = &KeyUsages{}
		}

		// Override with zero key usages object to handle static case
		if opts.OverrideDisableExtendedKeyUsageExtensions {
			req.ExtendedKeyUsages = nil
		}

		// Handle Explicit algorithm overrides.
		if opts.OverrideSignatureAlgorithm != nil {
			req.Signature.Algorithm = *opts.OverrideSignatureAlgorithm
		}
		if opts.OverrideSignatureHashAlgorithm != nil {
			req.Signature.HashAlgorithm = *opts.OverrideSignatureHashAlgorithm
		}
	}
	return req, nil
}

// ValidateIssueCertRequest Compare request against Validation Policy and remove static/forbidden fields
func (req *IssueCertRequest) ValidateIssueCertRequest(vp ValidationPolicy) error {

	// check if EKU's are static
	if vp.ExtendedKeyUsages.EKUs.Static == true {
		req.ExtendedKeyUsages = nil
	}

	//check ku
	if vp.KeyUsages.ContentCommitment == "STATIC_TRUE" || vp.KeyUsages.ContentCommitment == "STATIC_FALSE" {
		req.KeyUsages.ContentCommitment = nil
	}
	if vp.KeyUsages.CrlSign == "STATIC_TRUE" || vp.KeyUsages.CrlSign == "STATIC_FALSE" {
		req.KeyUsages.CrlSign = nil
	}
	if vp.KeyUsages.DataEncipherment == "STATIC_TRUE" || vp.KeyUsages.DataEncipherment == "STATIC_FALSE" {
		req.KeyUsages.DataEncipherment = nil
	}
	if vp.KeyUsages.DecipherOnly == "STATIC_TRUE" || vp.KeyUsages.DecipherOnly == "STATIC_FALSE" {
		req.KeyUsages.DecipherOnly = nil
	}
	if vp.KeyUsages.DigitalSignature == "STATIC_TRUE" || vp.KeyUsages.DigitalSignature == "STATIC_FALSE" {
		req.KeyUsages.DigitalSignature = nil
	}
	if vp.KeyUsages.EncipherOnly == "STATIC_TRUE" || vp.KeyUsages.EncipherOnly == "STATIC_FALSE" {
		req.KeyUsages.EncipherOnly = nil
	}
	if vp.KeyUsages.KeyAgreement == "STATIC_TRUE" || vp.KeyUsages.KeyAgreement == "STATIC_FALSE" {
		req.KeyUsages.KeyAgreement = nil
	}
	if vp.KeyUsages.KeyCertificateSign == "STATIC_TRUE" || vp.KeyUsages.KeyCertificateSign == "STATIC_FALSE" {
		req.KeyUsages.KeyCertificateSign = nil
	}
	if vp.KeyUsages.KeyEncipherment == "STATIC_TRUE" || vp.KeyUsages.KeyEncipherment == "STATIC_FALSE" {
		req.KeyUsages.KeyEncipherment = nil
	}

	// check hash_algorithm
	if vp.Signature.HashAlgorithm.Presence == "STATIC" {
		req.Signature.HashAlgorithm = ""
	}

	// check signature_hash_algorithm
	if vp.Signature.Algorithm.Presence == "STATIC" {
		req.Signature.Algorithm = ""
	}

	return nil

}

func marshalIPs(s []net.IP) []string {
	out := make([]string, len(s))
	for i, o := range s {
		out[i] = o.String()
	}
	return out
}

func marshalURIs(s []*url.URL) []string {
	out := make([]string, len(s))
	for i, o := range s {
		out[i] = o.String()
	}
	return out
}

var extendedKeyUsageOMapping = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth:                     "1.3.6.1.5.5.7.3.1",
	x509.ExtKeyUsageClientAuth:                     "1.3.6.1.5.5.7.3.2",
	x509.ExtKeyUsageCodeSigning:                    "1.3.6.1.5.5.7.3.3",
	x509.ExtKeyUsageEmailProtection:                "1.3.6.1.5.5.7.3.4",
	x509.ExtKeyUsageIPSECEndSystem:                 "1.3.6.1.5.5.7.3.5",
	x509.ExtKeyUsageIPSECTunnel:                    "1.3.6.1.5.5.7.3.6",
	x509.ExtKeyUsageIPSECUser:                      "1.3.6.1.5.5.7.3.7",
	x509.ExtKeyUsageTimeStamping:                   "1.3.6.1.5.5.7.3.8",
	x509.ExtKeyUsageOCSPSigning:                    "1.3.6.1.5.5.7.3.9",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "1.3.6.1.4.1.311.10.3.3",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "2.16.840.1.113730.4.1",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "1.3.6.1.4.1.311.2.1.22",
}

func marshalExtendedKeyUsage(s []x509.ExtKeyUsage) []string {
	out := []string{}
	for _, o := range s {
		// Silently ignore unknown IDs
		str, _ := extendedKeyUsageOMapping[o]
		if str != "" {
			out = append(out, str)
		}
	}
	return out
}

// used to handle UnknownKeyExtensions
func asn1OIDStr(ids []asn1.ObjectIdentifier) []string {
	out := make([]string, len(ids))
	for i, v := range ids {
		out[i] = v.String()
	}
	return out
}

// NewSubjectDN calculates the Subject DN payload based on the provided pkix.Name
func NewSubjectDN(sub *pkix.Name) *SubjectDN {
	return &SubjectDN{
		CommonName:         sub.CommonName,
		Country:            pickFirst(sub.Country),
		State:              pickFirst(sub.Province),
		Locality:           pickFirst(sub.Locality),
		StreetAddress:      pickFirst(sub.StreetAddress),
		Organization:       pickFirst(sub.Organization),
		OrganizationalUnit: sub.OrganizationalUnit,
	}
}

// pickFirst is a utility function which simply grabs the first element if any.
//
// Useful when working with x509 array attrs and Atlas.
func pickFirst(l []string) string {
	if len(l) == 0 {
		return ""
	}
	return l[0]
}
