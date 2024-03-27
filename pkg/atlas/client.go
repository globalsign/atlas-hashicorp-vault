// Package atlas is an GlobalSign Atlas API Client.
//
// GlobalSign Atlas API Documentation: https://www.globalsign.com/en/resources/apis/api-documentation/globalsign_hvca_api_documentation_version_v2.html
package atlas

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

const (
	loginPath = "/v2/login"

	defaultRetries        = 5
	defaultInitialBackoff = 500 * time.Millisecond
)

// ClientConfig represents configuration options available to the ATLAS client.
type ClientConfig struct {
	APIKey      *string
	APISecret   *string
	HVCAUrl     string
	Certificate *tls.Certificate

	// Retries is the number of attempts a 5XX class error or 202 status will be retried
	Retries int

	// InitialBackoff is the initial backoff used in the exponential backoff.
	InitialBackoff time.Duration
}

// Types requied to unmarshal Valiation Policy from HVCA
type (
	ValidationPolicy struct {
		ExtendedKeyUsages EKUPolicy       `json:"extended_key_usages,omitempty"`
		KeyUsages         KeyUsagePolicy  `json:"key_usages,omitempty"`
		Signature         SignaturePolicy `json:"signature,omitemtpy"`
	}

	EKUPolicy struct {
		EKUs     ListPolicy `json:"ekus"`
		Critical bool       `json:"critical"`
	}

	SignaturePolicy struct {
		Algorithm     SimpleListPolicy `json:"algorithm"`
		HashAlgorithm SimpleListPolicy `json:"hash_algorithm"`
	}

	KeyUsagePolicy struct {
		ContentCommitment  string `json:"content_commitment"`
		CrlSign            string `json:"crl_sign"`
		DataEncipherment   string `json:"data_encipherment"`
		DecipherOnly       string `json:"decipher_only"`
		DigitalSignature   string `json:"digital_signature"`
		EncipherOnly       string `json:"encipher_only"`
		KeyAgreement       string `json:"key_agreement"`
		KeyCertificateSign string `json:"key_certificate_sign"`
		KeyEncipherment    string `json:"key_encipherment"`
	}

	ListPolicy struct {
		Static   bool     `json:"static"`
		List     []string `json:"list"`
		MinCount int      `json:"mincount"`
		MaxCount int      `json:"maxcount"`
	}

	SimpleListPolicy struct {
		List     []string `json:"list"`
		Presence string   `json:"presence"`
	}
)

// Client acts as a interface between the local process and Globalsign ATLAS.
type Client interface {
	// Login performs the exchange of
	Login(ctx context.Context) error

	// GetConfig gets the configuration profile for your Atlas Instance, Refer to the API documentation for more info.
	GetConfig(ctx context.Context) (ValidationPolicy, error)

	// GetTrustChain returns the Certificate Authority chain used by the instance, output is an array of PEM encoded certs.
	GetTrustChain(ctx context.Context) ([]string, error)

	// IssueCertificate will that the provided CSR and Parameters to request issuance of a certificate from your Atlas Instance.
	IssueCertificate(ctx context.Context, req *IssueCertRequest) (*Certificate, error)

	// GetCert gets the certificate for the provided serial number.
	GetCert(ctx context.Context, id string) (*Certificate, error)
	// RevokeCert revokes the certificate with the provided serial number.
	RevokeCert(ctx context.Context, id string) error
}

// Client acts as a interface between the local process and Globalsign ATLAS.
type client struct {
	clientConfig *ClientConfig
	http         *http.Client
	accessToken  string
	tokenMutex   sync.RWMutex
}

// New constructs a ready to use ATLAS client.
func New(conf *ClientConfig) (Client, error) {
	if conf == nil {
		return nil, fmt.Errorf("ATLAS: must provide client config")
	}

	if conf.APIKey == nil || *conf.APIKey == "" {
		return nil, fmt.Errorf("ATLAS: must provide APIKey in config")
	}
	if conf.APISecret == nil || *conf.APISecret == "" {
		return nil, fmt.Errorf("ATLAS: must provide APISecret in config")
	}

	if conf.Certificate == nil {
		return nil, fmt.Errorf("ATLAS: must provide client certificate")
	}

	if conf.Retries == 0 {
		conf.Retries = defaultRetries
	}

	if conf.InitialBackoff == 0 {
		conf.InitialBackoff = defaultInitialBackoff
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{
				*conf.Certificate,
			},
		},
	}

	return &client{
		clientConfig: conf,
		http:         &http.Client{Transport: transport},
	}, nil
}

func (c *client) do(ctx context.Context, method, path string, body, outBody interface{}) (resp *http.Response, err error) {
	// Special Case: No access token indicates that we should login before dispatching the intended request.
	// Note: Login path condition needed to avoid recursion
	if c.getAccessToken() == "" && path != loginPath {
		if err := c.Login(ctx); err != nil {
			return nil, err
		}
	}

	backoff := c.clientConfig.InitialBackoff
	remainingRetries := c.clientConfig.Retries

	didTryAuth := false
	var doReq func() error
	doReq = func() error {
		var bodyIO io.Reader
		if body != nil {
			writableBody := bytes.NewBuffer([]byte{})
			bodyIO = writableBody
			if err = json.NewEncoder(writableBody).Encode(body); err != nil {
				return err
			}
		}

		req, err := http.NewRequest(method, c.clientConfig.HVCAUrl+path, bodyIO)
		if err != nil {
			return err
		}

		req.WithContext(ctx)

		req.Header.Add("Authorization", "Bearer "+c.getAccessToken())
		if body != nil {
			req.Header.Add("Content-Type", "application/json;charset=utf-8")
		}

		resp, err = c.http.Do(req)
		if err != nil {
			return err
		}
		defer consumeAndCloseResponseBody(resp)

		// Try to login if we haven't done so already in this instance, otherwise defer to error logic
		if resp.StatusCode == http.StatusUnauthorized && path != loginPath && !didTryAuth {
			didTryAuth = true
			if err := c.Login(ctx); err != nil {
				return err
			}
			return doReq()
		}

		// Check for error conditions
		// Not 200 == Error
		if resp.StatusCode/100 != 2 {

			// Parse into error struct
			errorBody := &APIError{}
			json.NewDecoder(resp.Body).Decode(&errorBody)
			errorBody.StatusCode = resp.StatusCode
			return errorBody
		}

		if outBody != nil {
			return json.NewDecoder(resp.Body).Decode(&outBody)
		}

		return nil
	}

	// Retry with exponential backoff
	for ; remainingRetries > 0; remainingRetries-- {
		err = doReq()
		// 5XX class errors are assumed to be retryable, 202 is also retryable on some endpoints so we will use the same logic there
		if resp != nil && (resp.StatusCode/100 == 5 || resp.StatusCode == http.StatusAccepted) {
			time.Sleep(backoff)
			backoff *= 2

			// Response Object exists and no error we assume its safe to return early without additional retries.
		} else if resp != nil && err == nil {
			return resp, err
		}
	}
	return resp, err
}

// Need to login also...

type loginReq struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}
type loginRes struct {
	AccessToken string `json:"access_token"`
}

// getAccessToken gets the access token in a concurently safe way.
func (c *client) getAccessToken() string {
	c.tokenMutex.RLock()
	defer c.tokenMutex.RUnlock()
	return c.accessToken
}

// Login performs the exchange of
func (c *client) Login(ctx context.Context) error {
	out := &loginRes{}
	_, err := c.do(ctx, http.MethodPost, loginPath, &loginReq{
		APIKey:    *c.clientConfig.APIKey,
		APISecret: *c.clientConfig.APISecret,
	}, out)
	if err != nil {
		return err
	}

	if out != nil {
		c.tokenMutex.Lock()
		defer c.tokenMutex.Unlock()
		c.accessToken = out.AccessToken
	}

	return nil
}

// GetConfig gets the configuration profile for your Atlas Instance, Refer to the API documentation for more info.
func (c *client) GetConfig(ctx context.Context) (ValidationPolicy, error) {
	out := ValidationPolicy{}
	if _, err := c.do(ctx, http.MethodGet, "/v2/validationpolicy", nil, &out); err != nil {
		return ValidationPolicy{}, err
	}
	return out, nil
}

// GetTrustChain returns the Certificate Authority chain used by the instance, output is an array of PEM encoded certs.
func (c *client) GetTrustChain(ctx context.Context) ([]string, error) {
	out := []string{}
	if _, err := c.do(ctx, http.MethodGet, "/v2/trustchain", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Certificate is the API structured object return by GlobalSign Atlas
type Certificate struct {
	// Status of the certificate typically ISSUED, or REVOKED
	Status string `json:"status"`

	// The PEM Encoded Certificate
	Certificate string `json:"certificate"`

	// UpdatedAt the time which the object was last updated, typically issuance or revocation time.
	UpdatedAt uint64 `json:"updated_at"`
}

// IssueCertificate will that the provided CSR and Parameters to request issuance of a certificate from your Atlas Instance.
//
// Note that this issuance call actually performs a Issue then GET for convince.
func (c *client) IssueCertificate(ctx context.Context, req *IssueCertRequest) (*Certificate, error) {
	out := &Certificate{}
	resp, err := c.do(ctx, http.MethodPost, "/v2/certificates", req, nil)
	if err != nil {
		return nil, err
	}

	// Assumption: Our target Host is somewhat trusted.
	// Worst Case Scenario Thoughts: The trusted host inserts a malicious host somehow, the malicious host
	//	 has a valid cert for its domain, which is not necessarily the Atlas Domain. We thus accept their cert in the mTLS handshake,
	//   they accept our certificate in the handshake, and is able to get the PlainText Short Lived Session token. The exposure of this
	//   values are mitigated because they also require the mTLS cert to use. The malicious actor would still need a method to retreive the
	//   mTLS private key, which would require an attack on the TLS protocol it self. Additionally the session token is short lived, and frequently
	//   rotated resulting in PFS for requests after token expiration.
	//
	//   I believe this is a reasonable risk to accept as the attack would require the compromise of TLS itself, which has far worse implications
	//   than getting access to an Atlas account.
	if _, err := c.do(ctx, http.MethodGet, resp.Header.Get("location"), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetCert gets the certificate for the provided serial number.
func (c *client) GetCert(ctx context.Context, id string) (*Certificate, error) {
	out := &Certificate{}
	if _, err := c.do(ctx, http.MethodGet, "/v2/certificates/"+id, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeCert revokes the certificate with the provided serial number.
func (c *client) RevokeCert(ctx context.Context, id string) error {
	if _, err := c.do(ctx, http.MethodDelete, "/v2/certificates/"+id, nil, nil); err != nil {
		return err
	}
	return nil
}

// consumeAndCloseResponseBody is designed to handle potential resource leaks from not fully consumed request bodies.
//
//	ref https://github.com/google/go-github/pull/317
func consumeAndCloseResponseBody(r *http.Response) {
	defer r.Body.Close()
	io.Copy(ioutil.Discard, r.Body)
}
