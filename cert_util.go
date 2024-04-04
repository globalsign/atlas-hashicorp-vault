package atlasvault

// ATLAS NOTE: Most of this code has been extracted from the Hashicorp Vault PKI Lib, this is to
//       maintain feature parity with PKI, and thus compatability systems that depend on that interface.
//
//       You should be able to drop in replace most code here to maintain parity.
//
//       While we've tried to keep the GlobalSign Atlas code seprate to support future growth, some functions
//       are modified, you can see this with comments in the function. These comments are to help with maintenance.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/globalsign/atlas-hashicorp-vault/pkg/atlas"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryanuber/go-glob"
	"golang.org/x/crypto/cryptobyte"
	cbbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/net/idna"
)

type certExtKeyUsage int

const (
	anyExtKeyUsage certExtKeyUsage = 1 << iota
	serverAuthExtKeyUsage
	clientAuthExtKeyUsage
	codeSigningExtKeyUsage
	emailProtectionExtKeyUsage
	ipsecEndSystemExtKeyUsage
	ipsecTunnelExtKeyUsage
	ipsecUserExtKeyUsage
	timeStampingExtKeyUsage
	ocspSigningExtKeyUsage
	microsoftServerGatedCryptoExtKeyUsage
	netscapeServerGatedCryptoExtKeyUsage
	microsoftCommercialCodeSigningExtKeyUsage
	microsoftKernelCodeSigningExtKeyUsage
)

// dataBundle comes from Vault PKI, it accumulates context of requests and makes calls re-usable
type dataBundle struct {
	params        *creationParameters
	signingBundle *caInfoBundle
	csr           *x509.CertificateRequest
	role          *roleEntry
	req           *logical.Request
	apiData       *framework.FieldData
}

// creationParameters are the values provided by vault issuance calls, this comes from Vault PKI;
//
//	maintained to support translation and future parameter support.
type creationParameters struct {
	Subject                       pkix.Name
	DNSNames                      []string
	EmailAddresses                []string
	IPAddresses                   []net.IP
	URIs                          []*url.URL
	OtherSANs                     map[string][]string
	IsCA                          bool
	KeyType                       string
	KeyBits                       int
	NotAfter                      time.Time
	KeyUsage                      x509.KeyUsage
	ExtKeyUsage                   certExtKeyUsage
	ExtKeyUsageOIDs               []string
	PolicyIdentifiers             []string
	BasicConstraintsValidForNonCA bool

	// Only used when signing a CA cert
	UseCSRValues        bool
	PermittedDNSDomains []string

	// URLs to encode into the certificate
	URLs *certutil.URLEntries

	// The maximum path length to encode
	MaxPathLength int
}

type caInfoBundle struct {
	certutil.ParsedCertBundle
	URLs *certutil.URLEntries
}

var (
	// A note on hostnameRegex: although we set the StrictDomainName option
	// when doing the idna conversion, this appears to only affect output, not
	// input, so it will allow e.g. host^123.example.com straight through. So
	// we still need to use this to check the output.
	hostnameRegex                = regexp.MustCompile(`^(\*\.)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
	oidExtensionBasicConstraints = []int{2, 5, 29, 19}
)

// odiInExtensions from Vault PKI
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// getFormat from Vault PKI
func getFormat(data *framework.FieldData) string {
	format := data.Get("format").(string)
	switch format {
	case "pem":
	case "der":
	case "pem_bundle":
	default:
		format = ""
	}
	return format
}

// validateKeyTypeLength from Vault PKI
func validateKeyTypeLength(keyType string, keyBits int) *logical.Response {
	switch keyType {
	case "rsa":
		switch keyBits {
		case 2048:
		case 4096:
		case 8192:
		default:
			return logical.ErrorResponse(fmt.Sprintf(
				"unsupported bit length for RSA key: %d", keyBits))
		}
	case "ec":
		switch keyBits {
		case 224:
		case 256:
		case 384:
		case 521:
		default:
			return logical.ErrorResponse(fmt.Sprintf(
				"unsupported bit length for EC key: %d", keyBits))
		}
	case "any":
	default:
		return logical.ErrorResponse(fmt.Sprintf(
			"unknown key type %s", keyType))
	}

	return nil
}

// fetchCertBySerial from vaultPKI, ATLAS_MODIFIED

// Allows fetching certificates from the Backend; it handles the slightly
// separate pathing for CA, CRL, and revoked certificates.
func fetchCertBySerial(ctx context.Context, req *logical.Request, prefix, serial string) (*logical.StorageEntry, error) {
	var path, legacyPath string
	var err error
	var certEntry *logical.StorageEntry

	hyphenSerial := normalizeSerial(serial)
	colonSerial := strings.Replace(strings.ToLower(serial), "-", ":", -1)

	switch {
	case strings.HasPrefix(prefix, "revoked/"):
		legacyPath = "revoked/" + colonSerial
		path = "revoked/" + hyphenSerial
	default:
		legacyPath = "certs/" + colonSerial
		path = "certs/" + hyphenSerial
	}

	certEntry, err = req.Storage.Get(ctx, path)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching certificate %s: %s", serial, err)}
	}
	if certEntry != nil {
		if certEntry.Value == nil || len(certEntry.Value) == 0 {
			return nil, errutil.InternalError{Err: fmt.Sprintf("returned certificate bytes for serial %s were empty", serial)}
		}
		return certEntry, nil
	}

	// If legacyPath is unset, it's going to be a CA or CRL; return immediately
	if legacyPath == "" {
		return nil, nil
	}

	// Retrieve the old-style path
	certEntry, err = req.Storage.Get(ctx, legacyPath)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching certificate %s: %s", serial, err)}
	}
	if certEntry == nil {
		return nil, nil
	}
	if certEntry.Value == nil || len(certEntry.Value) == 0 {
		return nil, errutil.InternalError{Err: fmt.Sprintf("returned certificate bytes for serial %s were empty", serial)}
	}

	// Update old-style paths to new-style paths
	certEntry.Key = path
	if err = req.Storage.Put(ctx, certEntry); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error saving certificate with serial %s to new location", serial)}
	}
	if err = req.Storage.Delete(ctx, legacyPath); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error deleting certificate with serial %s from old location", serial)}
	}

	return certEntry, nil
}

// validateNames from Vault PKI, to maintain role behavior and ACL.

// Given a set of requested names for a certificate, verifies that all of them
// match the various toggles set in the role for controlling issuance.
// If one does not pass, it is returned in the string argument.
func validateNames(data *dataBundle, names []string) string {
	for _, name := range names {
		sanitizedName := name
		emailDomain := name
		isEmail := false
		isWildcard := false

		// If it has an @, assume it is an email address and separate out the
		// user from the hostname portion so that we can act on the hostname.
		// Note that this matches behavior from the alt_names parameter. If it
		// ends up being problematic for users, I guess that could be separated
		// into dns_names and email_names in the future to be explicit, but I
		// don't think this is likely.
		if strings.Contains(name, "@") {
			splitEmail := strings.Split(name, "@")
			if len(splitEmail) != 2 {
				return name
			}
			sanitizedName = splitEmail[1]
			emailDomain = splitEmail[1]
			isEmail = true
		}

		// If we have an asterisk as the first part of the domain name, mark it
		// as wildcard and set the sanitized name to the remainder of the
		// domain
		if strings.HasPrefix(sanitizedName, "*.") {
			sanitizedName = sanitizedName[2:]
			isWildcard = true
		}

		// Email addresses using wildcard domain names do not make sense
		if isEmail && isWildcard {
			return name
		}

		// AllowAnyName is checked after this because EnforceHostnames still
		// applies when allowing any name. Also, we check the sanitized name to
		// ensure that we are not either checking a full email address or a
		// wildcard prefix.
		if data.role.EnforceHostnames {
			p := idna.New(
				idna.StrictDomainName(true),
				idna.VerifyDNSLength(true),
			)
			converted, err := p.ToASCII(sanitizedName)
			if err != nil {
				return name
			}
			if !hostnameRegex.MatchString(converted) {
				return name
			}
		}

		// Self-explanatory
		if data.role.AllowAnyName {
			continue
		}

		// The following blocks all work the same basic way:
		// 1) If a role allows a certain class of base (localhost, token
		// display name, role-configured domains), perform further tests
		//
		// 2) If there is a perfect match on either the name itself or it's an
		// email address with a perfect match on the hostname portion, allow it
		//
		// 3) If subdomains are allowed, we check based on the sanitized name;
		// note that if not a wildcard, will be equivalent to the email domain
		// for email checks, and we already checked above for both a wildcard
		// and email address being present in the same name
		// 3a) First we check for a non-wildcard subdomain, as in <name>.<base>
		// 3b) Then we check if it's a wildcard and the base domain is a match
		//
		// Variances are noted in-line

		if data.role.AllowLocalhost {
			if name == "localhost" ||
				name == "localdomain" ||
				(isEmail && emailDomain == "localhost") ||
				(isEmail && emailDomain == "localdomain") {
				continue
			}

			if data.role.AllowSubdomains {
				// It is possible, if unlikely, to have a subdomain of "localhost"
				if strings.HasSuffix(sanitizedName, ".localhost") ||
					(isWildcard && sanitizedName == "localhost") {
					continue
				}

				// A subdomain of "localdomain" is also not entirely uncommon
				if strings.HasSuffix(sanitizedName, ".localdomain") ||
					(isWildcard && sanitizedName == "localdomain") {
					continue
				}
			}
		}

		if len(data.role.AllowedDomains) > 0 {
			valid := false
			for _, currDomain := range data.role.AllowedDomains {
				// If there is, say, a trailing comma, ignore it
				if currDomain == "" {
					continue
				}

				// First, allow an exact match of the base domain if that role flag
				// is enabled
				if data.role.AllowBareDomains &&
					(name == currDomain ||
						(isEmail && emailDomain == currDomain)) {
					valid = true
					break
				}

				if data.role.AllowSubdomains {
					if strings.HasSuffix(sanitizedName, "."+currDomain) ||
						(isWildcard && sanitizedName == currDomain) {
						valid = true
						break
					}
				}

				if data.role.AllowGlobDomains &&
					strings.Contains(currDomain, "*") &&
					glob.Glob(currDomain, name) {
					valid = true
					break
				}
			}
			if valid {
				continue
			}
		}

		return name
	}

	return ""
}

// validateOtherSANs from Vault PKI to maintain role behavior.

// validateOtherSANs checks if the values requested are allowed. If an OID
// isn't allowed, it will be returned as the first string. If a value isn't
// allowed, it will be returned as the second string. Empty strings + error
// means everything is okay.
func validateOtherSANs(data *dataBundle, requested map[string][]string) (string, string, error) {
	allowed, err := parseOtherSANs(data.role.AllowedOtherSANs)
	if err != nil {
		return "", "", errwrap.Wrapf("error parsing role's allowed SANs: {{err}}", err)
	}
	for oid, names := range requested {
		for _, name := range names {
			allowedNames, ok := allowed[oid]
			if !ok {
				return oid, "", nil
			}

			valid := false
			for _, allowedName := range allowedNames {
				if glob.Glob(allowedName, name) {
					valid = true
					break
				}
			}

			if !valid {
				return oid, name, nil
			}
		}
	}

	return "", "", nil
}

// parseOtherSANs from Vault PKI to maintain role ACL behavior.
func parseOtherSANs(others []string) (map[string][]string, error) {
	result := map[string][]string{}
	for _, other := range others {
		splitOther := strings.SplitN(other, ";", 2)
		if len(splitOther) != 2 {
			return nil, fmt.Errorf("expected a semicolon in other SAN %q", other)
		}
		splitType := strings.SplitN(splitOther[1], ":", 2)
		if len(splitType) != 2 {
			return nil, fmt.Errorf("expected a colon in other SAN %q", other)
		}
		if strings.ToLower(splitType[0]) != "utf8" {
			return nil, fmt.Errorf("only utf8 other SANs are supported; found non-supported type in other SAN %q", other)
		}
		result[splitOther[0]] = append(result[splitOther[0]], splitType[1])
	}

	return result, nil
}

// trustChainToBlocks is an atlas helper, that converts the pem trust chain to golang certificate blocks.
//
//	It uses some Vault PKI helpers, which is why it resides here.
func trustChainToBlocks(ctx context.Context, client atlas.Client) ([]*certutil.CertBlock, error) {
	trustChain, err := client.GetTrustChain(ctx)
	if err != nil {
		return nil, errwrap.Wrapf("atlas Cert isssue: {{err}}", err)
	}

	chain := []*certutil.CertBlock{}
	for c := range trustChain {
		parsed, err := parsePem(trustChain[c])
		if err != nil {
			return nil, err
		}
		chain = append(chain, parsed)
	}
	return chain, nil
}

// generateCert Generates a Keypair and Issues a certificate through ATLAS.
//
// This code is derrived from Vault PKI to maintain interface support. CA validation behavior
//
//	has been removed as Atlas holds the CA, and CSR generation has been ported to a struct to support reusability,
//	finnally Issuance goes through the atlas client which is appended to the pre-existing signature.
func generateCert(ctx context.Context,
	b *Backend,
	data *dataBundle,
	isCA bool, client atlas.Client) (*certutil.ParsedCertBundle, error) {
	result := &certutil.ParsedCertBundle{}

	// Begin ACL Checks
	if data.role == nil {
		return nil, errutil.InternalError{Err: "no role found in data bundle"}
	}

	if data.role.KeyType == "rsa" && data.role.KeyBits < 2048 {
		return nil, errutil.UserError{Err: "RSA keys < 2048 bits are unsafe and not supported"}
	}

	// Begin Key and CSR generation
	err := generateCreationBundle(b, data)
	if err != nil {
		return nil, err
	}
	if data.params == nil {
		return nil, errutil.InternalError{Err: "nil parameters received from parameter bundle generation"}
	}

	// Begin Internal PKI request to Atlas Translation
	hcsr := &atlasCertRequest{}
	if err := hcsr.GenerateCSR(data); err != nil {
		return nil, err
	}

	// CSR to pem
	req, err := atlas.NewIssueCertRequest(hcsr.CSR, hcsr.CertTemplate, b.issuanceOptions)
	if err != nil {
		return nil, errutil.UserError{Err: "Invalid Certificate Request Parameters"}
	}

	// Get Validation Policy
	vp, err := client.GetConfig(ctx)
	if err != nil {
		return nil, errutil.UserError{Err: "Unable to retrieve validation policy"}
	}

	// Check Request Against Validation Policy
	err = req.ValidateIssueCertRequest(vp)
	if err != nil {
		return nil, errutil.UserError{Err: "Unable to Validate Request against Validation Policy: " + err.Error()}
	}

	issued, err := client.IssueCertificate(ctx, req)
	if err != nil {
		return nil, errutil.UserError{Err: "Failed to issue cert in Atlas: " + err.Error()}
	}

	// Begin Response formatting
	cert, err := parsePem(issued.Certificate)
	if err != nil {
		return nil, errutil.InternalError{Err: "Failed to format Atlas response"}
	}

	// Need to request additional data to service the request
	trustChain, err := client.GetTrustChain(ctx)
	if err != nil {
		return nil, errutil.InternalError{Err: "Failed to get trust chain from Atlas: " + err.Error()}
	}

	chain := []*certutil.CertBlock{}
	for c := range trustChain {
		parsed, err := parsePem(trustChain[c])
		if err != nil {
			return nil, err
		}
		chain = append(chain, parsed)
	}

	result.PrivateKeyType = hcsr.PrivateKey.Type
	result.PrivateKeyBytes = hcsr.PrivateKey.Bytes
	result.PrivateKey = hcsr.PrivateKey.Signer
	result.CertificateBytes = cert.Bytes
	result.Certificate = cert.Certificate
	result.CAChain = chain

	return result, nil
}

// parsePem converts a PEM to a hashicorp vault CertBlock
func parsePem(pems string) (*certutil.CertBlock, error) {
	certBlock, _ := pem.Decode([]byte(pems))
	if certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM was not cert")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &certutil.CertBlock{
		Certificate: cert,
		Bytes:       certBlock.Bytes,
	}, nil
}

// signCert perfoms ACL checks and signs a CSR like a normal RA (Not Needing the Private Key).
//
// Note: This was pulled from Vault PKI to maintain functional parity, its been modified to use atlas.
func signCert(ctx context.Context, b *Backend,
	data *dataBundle,
	isCA bool,
	useCSRValues bool,
	atlasClient atlas.Client) (*certutil.ParsedCertBundle, error) {

	// Begin ACL Checks
	if data.role == nil {
		return nil, errutil.InternalError{Err: "no role found in data bundle"}
	}

	csrString := data.apiData.Get("csr").(string)
	if csrString == "" {
		return nil, errutil.UserError{Err: fmt.Sprintf("\"csr\" is empty")}
	}

	pemBytes := []byte(csrString)
	pemBlock, pemBytes := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errutil.UserError{Err: "csr contains no data"}
	}
	csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, errutil.UserError{Err: fmt.Sprintf("certificate request could not be parsed: %v", err)}
	}

	switch data.role.KeyType {
	case "rsa":
		// Verify that the key matches the role type
		if csr.PublicKeyAlgorithm != x509.RSA {
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"role requires keys of type %s",
				data.role.KeyType)}
		}
		pubKey, ok := csr.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errutil.UserError{Err: "could not parse CSR's public key"}
		}

		// Verify that the key is at least 2048 bits
		if pubKey.N.BitLen() < 2048 {
			return nil, errutil.UserError{Err: "RSA keys < 2048 bits are unsafe and not supported"}
		}

		// Verify that the bit size is at least the size specified in the role
		if pubKey.N.BitLen() < data.role.KeyBits {
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"role requires a minimum of a %d-bit key, but CSR's key is %d bits",
				data.role.KeyBits,
				pubKey.N.BitLen())}
		}

	case "ec":
		// Verify that the key matches the role type
		if csr.PublicKeyAlgorithm != x509.ECDSA {
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"role requires keys of type %s",
				data.role.KeyType)}
		}
		pubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errutil.UserError{Err: "could not parse CSR's public key"}
		}

		// Verify that the bit size is at least the size specified in the role
		if pubKey.Params().BitSize < data.role.KeyBits {
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"role requires a minimum of a %d-bit key, but CSR's key is %d bits",
				data.role.KeyBits,
				pubKey.Params().BitSize)}
		}

	case "any":
		// We only care about running RSA < 2048 bit checks, so if not RSA
		// break out
		if csr.PublicKeyAlgorithm != x509.RSA {
			break
		}

		// Run RSA < 2048 bit checks
		pubKey, ok := csr.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errutil.UserError{Err: "could not parse CSR's public key"}
		}
		if pubKey.N.BitLen() < 2048 {
			return nil, errutil.UserError{Err: "RSA keys < 2048 bits are unsafe and not supported"}
		}

	}

	data.csr = csr

	// Begin Translating CSR to Request Object
	err = generateCreationBundle(b, data)
	if err != nil {
		return nil, err
	}
	if data.params == nil {
		return nil, errutil.InternalError{Err: "nil parameters received from parameter bundle generation"}
	}

	data.params.UseCSRValues = useCSRValues

	// Perform the actual Atlas Signing logic in the below function
	parsedBundle, err := signCertificate(ctx, data, []byte(csrString), atlasClient, b.issuanceOptions)
	if err != nil {
		return nil, err
	}

	return parsedBundle, nil
}

// generateCreationBundle is a shared function that reads parameters supplied
// from the various endpoints and generates a creationParameters with the
// parameters that can be used to issue or sign
//
// Pulled from Vault PKI, Modified for Atlas Support.
func generateCreationBundle(b *Backend, data *dataBundle) error {
	// Read in names -- CN, DNS and email addresses
	var cn string
	dnsNames := []string{}
	emailAddresses := []string{}
	{
		if data.csr != nil && data.role.UseCSRCommonName {
			cn = data.csr.Subject.CommonName
		}
		if cn == "" {
			cn = data.apiData.Get("common_name").(string)
			if cn == "" && data.role.RequireCN {
				return errutil.UserError{Err: `the common_name field is required, or must be provided in a CSR with "use_csr_common_name" set to true, unless "require_cn" is set to false`}
			}
		}

		if data.csr != nil && data.role.UseCSRSANs {
			dnsNames = data.csr.DNSNames
			emailAddresses = data.csr.EmailAddresses
		}

		if cn != "" && !data.apiData.Get("exclude_cn_from_sans").(bool) {
			if strings.Contains(cn, "@") {
				// Note: emails are not disallowed if the role's email protection
				// flag is false, because they may well be included for
				// informational purposes; it is up to the verifying party to
				// ensure that email addresses in a subject alternate name can be
				// used for the purpose for which they are presented
				emailAddresses = append(emailAddresses, cn)
			} else {
				// Only add to dnsNames if it's actually a DNS name but convert
				// idn first
				p := idna.New(
					idna.StrictDomainName(true),
					idna.VerifyDNSLength(true),
				)
				converted, err := p.ToASCII(cn)
				if err != nil {
					return errutil.UserError{Err: err.Error()}
				}
				if hostnameRegex.MatchString(converted) {
					dnsNames = append(dnsNames, converted)
				}
			}
		}

		if data.csr == nil || !data.role.UseCSRSANs {
			cnAltRaw, ok := data.apiData.GetOk("alt_names")
			if ok {
				cnAlt := strutil.ParseDedupLowercaseAndSortStrings(cnAltRaw.(string), ",")
				for _, v := range cnAlt {
					if strings.Contains(v, "@") {
						emailAddresses = append(emailAddresses, v)
					} else {
						// Only add to dnsNames if it's actually a DNS name but
						// convert idn first
						p := idna.New(
							idna.StrictDomainName(true),
							idna.VerifyDNSLength(true),
						)
						converted, err := p.ToASCII(v)
						if err != nil {
							return errutil.UserError{Err: err.Error()}
						}
						if hostnameRegex.MatchString(converted) {
							dnsNames = append(dnsNames, converted)
						}
					}
				}
			}
		}

		// Check the CN. This ensures that the CN is checked even if it's
		// excluded from SANs.
		if cn != "" {
			badName := validateNames(data, []string{cn})
			if len(badName) != 0 {
				return errutil.UserError{Err: fmt.Sprintf(
					"common name %s not allowed by this role", badName)}
			}
		}

		// Check for bad email and/or DNS names
		badName := validateNames(data, dnsNames)
		if len(badName) != 0 {
			return errutil.UserError{Err: fmt.Sprintf(
				"subject alternate name %s not allowed by this role", badName)}
		}

		badName = validateNames(data, emailAddresses)
		if len(badName) != 0 {
			return errutil.UserError{Err: fmt.Sprintf(
				"email address %s not allowed by this role", badName)}
		}
	}

	var otherSANs map[string][]string
	if sans := data.apiData.Get("other_sans").([]string); len(sans) > 0 {
		requested, err := parseOtherSANs(sans)
		if err != nil {
			return errutil.UserError{Err: errwrap.Wrapf("could not parse requested other SAN: {{err}}", err).Error()}
		}
		badOID, badName, err := validateOtherSANs(data, requested)
		switch {
		case err != nil:
			return errutil.UserError{Err: err.Error()}
		case len(badName) > 0:
			return errutil.UserError{Err: fmt.Sprintf(
				"other SAN %s not allowed for OID %s by this role", badName, badOID)}
		case len(badOID) > 0:
			return errutil.UserError{Err: fmt.Sprintf(
				"other SAN OID %s not allowed by this role", badOID)}
		default:
			otherSANs = requested
		}
	}

	// Get and verify any IP SANs
	ipAddresses := []net.IP{}
	{
		if data.csr != nil && data.role.UseCSRSANs {
			if len(data.csr.IPAddresses) > 0 {
				if !data.role.AllowIPSANs {
					return errutil.UserError{Err: fmt.Sprintf(
						"IP Subject Alternative Names are not allowed in this role, but was provided some via CSR")}
				}
				ipAddresses = data.csr.IPAddresses
			}
		} else {
			ipAlt := data.apiData.Get("ip_sans").([]string)
			if len(ipAlt) > 0 {
				if !data.role.AllowIPSANs {
					return errutil.UserError{Err: fmt.Sprintf(
						"IP Subject Alternative Names are not allowed in this role, but was provided %s", ipAlt)}
				}
				for _, v := range ipAlt {
					parsedIP := net.ParseIP(v)
					if parsedIP == nil {
						return errutil.UserError{Err: fmt.Sprintf(
							"the value '%s' is not a valid IP address", v)}
					}
					ipAddresses = append(ipAddresses, parsedIP)
				}
			}
		}
	}

	URIs := []*url.URL{}
	{
		if data.csr != nil && data.role.UseCSRSANs {
			if len(data.csr.URIs) > 0 {
				if len(data.role.AllowedURISANs) == 0 {
					return errutil.UserError{Err: fmt.Sprintf(
						"URI Subject Alternative Names are not allowed in this role, but were provided via CSR"),
					}
				}

				// validate uri sans
				for _, uri := range data.csr.URIs {
					valid := false
					for _, allowed := range data.role.AllowedURISANs {
						validURI := glob.Glob(allowed, uri.String())
						if validURI {
							valid = true
							break
						}
					}

					if !valid {
						return errutil.UserError{Err: fmt.Sprintf(
							"URI Subject Alternative Names were provided via CSR which are not valid for this role"),
						}
					}

					URIs = append(URIs, uri)
				}
			}
		} else {
			uriAlt := data.apiData.Get("uri_sans").([]string)
			if len(uriAlt) > 0 {
				if len(data.role.AllowedURISANs) == 0 {
					return errutil.UserError{Err: fmt.Sprintf(
						"URI Subject Alternative Names are not allowed in this role, but were provided via the API"),
					}
				}

				for _, uri := range uriAlt {
					valid := false
					for _, allowed := range data.role.AllowedURISANs {
						validURI := glob.Glob(allowed, uri)
						if validURI {
							valid = true
							break
						}
					}

					if !valid {
						return errutil.UserError{Err: fmt.Sprintf(
							"URI Subject Alternative Names were provided via CSR which are not valid for this role"),
						}
					}

					parsedURI, err := url.Parse(uri)
					if parsedURI == nil || err != nil {
						return errutil.UserError{Err: fmt.Sprintf(
							"the provided URI Subject Alternative Name '%s' is not a valid URI", uri),
						}
					}

					URIs = append(URIs, parsedURI)
				}
			}
		}
	}

	subject := pkix.Name{
		CommonName:         cn,
		Country:            strutil.RemoveDuplicates(data.role.Country, false),
		Organization:       strutil.RemoveDuplicates(data.role.Organization, false),
		OrganizationalUnit: strutil.RemoveDuplicates(data.role.OU, false),
		Locality:           strutil.RemoveDuplicates(data.role.Locality, false),
		Province:           strutil.RemoveDuplicates(data.role.Province, false),
		StreetAddress:      strutil.RemoveDuplicates(data.role.StreetAddress, false),
		PostalCode:         strutil.RemoveDuplicates(data.role.PostalCode, false),
	}

	// Get the TTL and verify it against the max allowed
	var ttl time.Duration
	var maxTTL time.Duration
	var notAfter time.Time
	{
		ttl = time.Duration(data.apiData.Get("ttl").(int)) * time.Second

		if ttl == 0 && data.role.TTL > 0 {
			ttl = data.role.TTL
		}

		if data.role.MaxTTL > 0 {
			maxTTL = data.role.MaxTTL
		}

		if ttl == 0 {
			ttl = b.System().DefaultLeaseTTL()
		}
		if maxTTL == 0 {
			maxTTL = b.System().MaxLeaseTTL()
		}
		if ttl > maxTTL {
			ttl = maxTTL
		}

		notAfter = time.Now().Add(ttl)

		// If it's not self-signed, verify that the issued certificate won't be
		// valid past the lifetime of the CA certificate
		if data.signingBundle != nil &&
			notAfter.After(data.signingBundle.Certificate.NotAfter) && !data.role.AllowExpirationPastCA {

			return errutil.UserError{Err: fmt.Sprintf(
				"cannot satisfy request, as TTL would result in notAfter %s that is beyond the expiration of the CA certificate at %s", notAfter.Format(time.RFC3339Nano), data.signingBundle.Certificate.NotAfter.Format(time.RFC3339Nano))}
		}
	}

	data.params = &creationParameters{
		Subject:                       subject,
		DNSNames:                      dnsNames,
		EmailAddresses:                emailAddresses,
		IPAddresses:                   ipAddresses,
		URIs:                          URIs,
		OtherSANs:                     otherSANs,
		KeyType:                       data.role.KeyType,
		KeyBits:                       data.role.KeyBits,
		NotAfter:                      notAfter,
		KeyUsage:                      x509.KeyUsage(parseKeyUsages(data.role.KeyUsage)),
		ExtKeyUsage:                   parseExtKeyUsages(data.role),
		ExtKeyUsageOIDs:               data.role.ExtKeyUsageOIDs,
		PolicyIdentifiers:             data.role.PolicyIdentifiers,
		BasicConstraintsValidForNonCA: data.role.BasicConstraintsValidForNonCA,
	}

	return nil
}

// addKeyUsages adds appropriate key usages to the template given the creation
// information
func addKeyUsages(data *dataBundle, certTemplate *x509.Certificate) {
	if data.params.IsCA {
		certTemplate.KeyUsage = x509.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign)
		return
	}

	certTemplate.KeyUsage = data.params.KeyUsage

	if data.params.ExtKeyUsage&anyExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageAny)
	}

	if data.params.ExtKeyUsage&serverAuthExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	if data.params.ExtKeyUsage&clientAuthExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	if data.params.ExtKeyUsage&codeSigningExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
	}

	if data.params.ExtKeyUsage&emailProtectionExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	if data.params.ExtKeyUsage&ipsecEndSystemExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageIPSECEndSystem)
	}

	if data.params.ExtKeyUsage&ipsecTunnelExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageIPSECTunnel)
	}

	if data.params.ExtKeyUsage&ipsecUserExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageIPSECUser)
	}

	if data.params.ExtKeyUsage&timeStampingExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageTimeStamping)
	}

	if data.params.ExtKeyUsage&ocspSigningExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning)
	}

	if data.params.ExtKeyUsage&microsoftServerGatedCryptoExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageMicrosoftServerGatedCrypto)
	}

	if data.params.ExtKeyUsage&netscapeServerGatedCryptoExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageNetscapeServerGatedCrypto)
	}

	if data.params.ExtKeyUsage&microsoftCommercialCodeSigningExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
	}

	if data.params.ExtKeyUsage&microsoftKernelCodeSigningExtKeyUsage != 0 {
		certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, x509.ExtKeyUsageMicrosoftKernelCodeSigning)
	}
}

// addPolicyIdentifiers adds certificate policies extension
func addPolicyIdentifiers(data *dataBundle, certTemplate *x509.Certificate) {
	for _, oidstr := range data.params.PolicyIdentifiers {
		oid, err := stringToOid(oidstr)
		if err == nil {
			certTemplate.PolicyIdentifiers = append(certTemplate.PolicyIdentifiers, oid)
		}
	}
}

// addExtKeyUsageOids adds custom extended key usage OIDs to certificate
func addExtKeyUsageOids(data *dataBundle, certTemplate *x509.Certificate) {
	for _, oidstr := range data.params.ExtKeyUsageOIDs {
		oid, err := stringToOid(oidstr)
		if err == nil {
			certTemplate.UnknownExtKeyUsage = append(certTemplate.UnknownExtKeyUsage, oid)
		}
	}
}

// Performs the heavy lifting of generating a certificate from a CSR.
// Returns a ParsedCertBundle sans private keys.
func signCertificate(ctx context.Context, data *dataBundle, pemCSR []byte, atlasClient atlas.Client, opts *atlas.CertRequestOptions) (*certutil.ParsedCertBundle, error) {
	switch {
	case data == nil:
		return nil, errutil.UserError{Err: "nil data bundle given to signCertificate"}
	case data.params == nil:
		return nil, errutil.UserError{Err: "nil parameters given to signCertificate"}
	case data.csr == nil:
		return nil, errutil.UserError{Err: "nil csr given to signCertificate"}
	}

	err := data.csr.CheckSignature()
	if err != nil {
		return nil, errutil.UserError{Err: "request signature invalid"}
	}

	result := &certutil.ParsedCertBundle{}

	serialNumber, err := certutil.GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	marshaledKey, err := x509.MarshalPKIXPublicKey(data.csr.PublicKey)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error marshalling public key: %s", err)}
	}
	subjKeyID := sha1.Sum(marshaledKey)

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      data.params.Subject,
		NotBefore:    time.Now().Add(-30 * time.Second),
		NotAfter:     data.params.NotAfter,
		SubjectKeyId: subjKeyID[:],
	}

	if data.params.UseCSRValues {
		certTemplate.Subject = data.csr.Subject

		certTemplate.DNSNames = data.csr.DNSNames
		certTemplate.EmailAddresses = data.csr.EmailAddresses
		certTemplate.IPAddresses = data.csr.IPAddresses
		certTemplate.URIs = data.csr.URIs

		for _, name := range data.csr.Extensions {
			if !name.Id.Equal(oidExtensionBasicConstraints) {
				certTemplate.ExtraExtensions = append(certTemplate.ExtraExtensions, name)
			}
		}

	} else {
		certTemplate.DNSNames = data.params.DNSNames
		certTemplate.EmailAddresses = data.params.EmailAddresses
		certTemplate.IPAddresses = data.params.IPAddresses
		certTemplate.URIs = data.csr.URIs
	}

	if err := handleOtherSANs(certTemplate, data.params.OtherSANs); err != nil {
		return nil, errutil.InternalError{Err: errwrap.Wrapf("error marshaling other SANs: {{err}}", err).Error()}
	}

	addPolicyIdentifiers(data, certTemplate)

	addKeyUsages(data, certTemplate)

	addExtKeyUsageOids(data, certTemplate)

	if data.params.BasicConstraintsValidForNonCA {
		certTemplate.BasicConstraintsValid = true
		certTemplate.IsCA = false
	}

	if len(data.params.PermittedDNSDomains) > 0 {
		certTemplate.PermittedDNSDomains = data.params.PermittedDNSDomains
		certTemplate.PermittedDNSDomainsCritical = true
	}

	// CSR to pem
	csrBlock, _ := pem.Decode(pemCSR)
	if csrBlock == nil {
		return nil, errutil.InternalError{Err: "unable to parse CSR PEM"}
	}
	req, err := atlas.NewIssueCertRequest(csrBlock.Bytes, certTemplate, opts)
	if err != nil {
		return nil, err
	}

	// Get Validation Policy
	vp, err := atlasClient.GetConfig(ctx)
	if err != nil {
		return nil, errutil.UserError{Err: "Unable to retrieve validation policy"}
	}
	// Check Request Against Validation Policy
	err = req.ValidateIssueCertRequest(vp)
	if err != nil {
		return nil, errutil.UserError{Err: "Unable to Validate Request against Validation Policy: " + err.Error()}
	}

	issued, err := atlasClient.IssueCertificate(ctx, req)
	if err != nil {
		return nil, errutil.UserError{Err: "Failed to issue cert in Atlas: " + err.Error()}
	}

	certBlock, _ := pem.Decode([]byte(issued.Certificate))
	if certBlock == nil {
		return nil, errutil.InternalError{Err: "unable to parse certificate PEM"}
	}
	result.CertificateBytes = certBlock.Bytes
	result.Certificate, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to parse created certificate: %s", err)}
	}

	result.CAChain, err = trustChainToBlocks(ctx, atlasClient)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("Unable to get trust chain: %s", err)}
	}

	return result, nil
}

// Pulled from Vault PKI to support interface.
func convertRespToPKCS8(resp *logical.Response) error {
	privRaw, ok := resp.Data["private_key"]
	if !ok {
		return nil
	}
	priv, ok := privRaw.(string)
	if !ok {
		return fmt.Errorf("error converting response to pkcs8: could not parse original value as string")
	}

	privKeyTypeRaw, ok := resp.Data["private_key_type"]
	if !ok {
		return fmt.Errorf("error converting response to pkcs8: %q not found in response", "private_key_type")
	}
	privKeyType, ok := privKeyTypeRaw.(certutil.PrivateKeyType)
	if !ok {
		return fmt.Errorf("error converting response to pkcs8: could not parse original type value as string")
	}

	var keyData []byte
	var pemUsed bool
	var err error
	var signer crypto.Signer

	block, _ := pem.Decode([]byte(priv))
	if block == nil {
		keyData, err = base64.StdEncoding.DecodeString(priv)
		if err != nil {
			return errwrap.Wrapf("error converting response to pkcs8: error decoding original value: {{err}}", err)
		}
	} else {
		keyData = block.Bytes
		pemUsed = true
	}

	switch privKeyType {
	case certutil.RSAPrivateKey:
		signer, err = x509.ParsePKCS1PrivateKey(keyData)
	case certutil.ECPrivateKey:
		signer, err = x509.ParseECPrivateKey(keyData)
	default:
		return fmt.Errorf("unknown private key type %q", privKeyType)
	}
	if err != nil {
		return errwrap.Wrapf("error converting response to pkcs8: error parsing previous key: {{err}}", err)
	}

	keyData, err = x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return errwrap.Wrapf("error converting response to pkcs8: error marshaling pkcs8 key: {{err}}", err)
	}

	if pemUsed {
		block.Type = "PRIVATE KEY"
		block.Bytes = keyData
		resp.Data["private_key"] = strings.TrimSpace(string(pem.EncodeToMemory(block)))
	} else {
		resp.Data["private_key"] = base64.StdEncoding.EncodeToString(keyData)
	}

	return nil
}

// Pulled from Vault PKI to support interface.
func handleOtherCSRSANs(in *x509.CertificateRequest, sans map[string][]string) error {
	certTemplate := &x509.Certificate{
		DNSNames:       in.DNSNames,
		IPAddresses:    in.IPAddresses,
		EmailAddresses: in.EmailAddresses,
		URIs:           in.URIs,
	}
	if err := handleOtherSANs(certTemplate, sans); err != nil {
		return err
	}
	if len(certTemplate.ExtraExtensions) > 0 {
		for _, v := range certTemplate.ExtraExtensions {
			in.ExtraExtensions = append(in.ExtraExtensions, v)
		}
	}
	return nil
}

// Pulled from Vault PKI to support interface.
func handleOtherSANs(in *x509.Certificate, sans map[string][]string) error {
	// If other SANs is empty we return which causes normal Go stdlib parsing
	// of the other SAN types
	if len(sans) == 0 {
		return nil
	}

	var rawValues []asn1.RawValue

	// We need to generate an IMPLICIT sequence for compatibility with OpenSSL
	// -- it's an open question what the default for RFC 5280 actually is, see
	// https://github.com/openssl/openssl/issues/5091 -- so we have to use
	// cryptobyte because using the asn1 package's marshaling always produces
	// an EXPLICIT sequence. Note that asn1 is way too magical according to
	// agl, and cryptobyte is modeled after the CBB/CBS bits that agl put into
	// boringssl.
	for oid, vals := range sans {
		for _, val := range vals {
			var b cryptobyte.Builder
			oidStr, err := stringToOid(oid)
			if err != nil {
				return err
			}
			b.AddASN1ObjectIdentifier(oidStr)
			b.AddASN1(cbbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbbasn1.UTF8String, func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(val))
				})
			})
			m, err := b.Bytes()
			if err != nil {
				return err
			}
			rawValues = append(rawValues, asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: m})
		}
	}

	// If other SANs is empty we return which causes normal Go stdlib parsing
	// of the other SAN types
	if len(rawValues) == 0 {
		return nil
	}

	// Append any existing SANs, sans marshalling
	rawValues = append(rawValues, marshalSANs(in.DNSNames, in.EmailAddresses, in.IPAddresses, in.URIs)...)

	// Marshal and add to ExtraExtensions
	ext := pkix.Extension{
		// This is the defined OID for subjectAltName
		Id: asn1.ObjectIdentifier{2, 5, 29, 17},
	}
	var err error
	ext.Value, err = asn1.Marshal(rawValues)
	if err != nil {
		return err
	}
	in.ExtraExtensions = append(in.ExtraExtensions, ext)

	return nil
}

// Pulled from Vault PKI to support interface.
//
// Note: Taken from the Go source code since it's not public, and used in the
// modified function below (which also uses these consts upstream)
const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// Pulled from Vault PKI to support interface.
//
// Note: Taken from the Go source code since it's not public, plus changed to not marshal
// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) []asn1.RawValue {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uri.String())})
	}
	return rawValues
}

// Pulled from Vault PKI to support interface.
func stringToOid(in string) (asn1.ObjectIdentifier, error) {
	split := strings.Split(in, ".")
	ret := make(asn1.ObjectIdentifier, 0, len(split))
	for _, v := range split {
		i, err := strconv.Atoi(v)
		if err != nil {
			return nil, err
		}
		ret = append(ret, i)
	}
	return asn1.ObjectIdentifier(ret), nil
}
