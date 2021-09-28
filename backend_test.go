package atlasvault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/globalsign/atlas-hashicorp-vault/pkg/atlas"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

var testKeyLocation = ""

func loadAtlasTestCreds() (*TestCreds, error) {
	if testKeyLocation == "" {
		testKeyLocation = "./.private/dev-creds/"
	}

	apif, err := os.Open(testKeyLocation + "api.json")
	if err != nil {
		return nil, err
	}
	apiOut := struct {
		User struct {
			APIKey    string `json:"api_key"`
			APISecret string `json:"api_secret"`
		} `json:"user"`
	}{}
	json.NewDecoder(apif).Decode(&apiOut)

	// Read Cert
	clientCertFile, err := ioutil.ReadFile(testKeyLocation + "cert.pem")
	if err != nil {
		return nil, err
	}

	clientCertKeyFile, err := ioutil.ReadFile(testKeyLocation + "key.pem")
	if err != nil {
		return nil, err
	}

	return &TestCreds{
		Key:     apiOut.User.APIKey,
		Secret:  apiOut.User.APISecret,
		CertKey: base64.StdEncoding.EncodeToString(clientCertKeyFile),
		Cert:    base64.StdEncoding.EncodeToString(clientCertFile),
	}, nil

}

func TestBackend(t *testing.T) {

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	Factory(context.TODO(), &logical.BackendConfig{})
}

func TestBackend_IssueCert(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	tc, err := loadAtlasTestCreds()
	if err != nil {
		t.Fatalf("bad: err: %v", err)
	}

	caData := map[string]interface{}{
		"api_key":      tc.Key,
		"api_secret":   tc.Secret,
		"api_cert":     tc.Cert,
		"api_cert_key": tc.CertKey,
	}

	caReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "config/authn",
		Storage:     storage,
		Data:        caData,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), caReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	assert.NoError(t, err)

	roleData := map[string]interface{}{
		"allow_any_name":     true,
		"enforce_hostnames":  false,
		"allowed_uri_sans":   "https://test.com/*",
		"ext_key_usage_oids": "1.3.6.1.5.5.7.3.8",
		"policy_identifiers": "1.3.6.1.5.5.7.3.8",
		"ttl":                "2h",
		"max_ttl":            "3h",
	}

	roleReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "roles/testrole",
		Storage:     storage,
		Data:        roleData,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	issueData := map[string]interface{}{
		"common_name":        "Hello World",
		"uri_sans":           "https://test.com/test/data?q",
		"format":             "pem",
		"private_key_format": "pkcs8",
	}
	issueReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "issue/testrole",
		Storage:     storage,
		Data:        issueData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	listReq := &logical.Request{
		Operation:   logical.ListOperation,
		Path:        "certs",
		Storage:     storage,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	for _, v := range resp.Data["keys"].([]string) {
		getReq := &logical.Request{
			Operation:   logical.ReadOperation,
			Path:        "cert/" + v,
			Storage:     storage,
			ClientToken: "sample",
		}

		resp, err = b.HandleRequest(context.Background(), getReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("bad: err: %v resp: %#v", err, resp)
		}
		getReq = &logical.Request{
			Operation:   logical.UpdateOperation,
			Path:        "revoke",
			Storage:     storage,
			ClientToken: "sample",
			Data: map[string]interface{}{
				"serial_number": v,
			},
		}

		resp, err = b.HandleRequest(context.Background(), getReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("bad: err: %v resp: %#v", err, resp)
		}
	}
}

func TestBackend_GetCertChain(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	tc, err := loadAtlasTestCreds()
	if err != nil {
		t.Fatalf("bad: err: %v", err)
	}

	caData := map[string]interface{}{
		"api_key":      tc.Key,
		"api_secret":   tc.Secret,
		"api_cert":     tc.Cert,
		"api_cert_key": tc.CertKey,
	}

	caReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "config/authn",
		Storage:     storage,
		Data:        caData,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), caReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	roleReq := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "cert/ca_chain",
		Storage:     storage,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

}

func TestBackend_GetCA(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	roleReq := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "ca",
		Storage:     storage,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	roleReq = &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "ca/pem",
		Storage:     storage,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}
}

func TestBackend_RolesA(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	roleData := map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"ttl":               "2h",
	}

	roleReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "roles/testrole",
		Storage:     storage,
		Data:        roleData,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	roleReq = &logical.Request{
		Operation:   logical.ListOperation,
		Path:        "roles",
		Storage:     storage,
		Data:        roleData,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	roleReq = &logical.Request{
		Operation:   logical.DeleteOperation,
		Path:        "roles/testrole",
		Storage:     storage,
		Data:        roleData,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

}

func TestBackend_SignCert_ecc(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	tc, err := loadAtlasTestCreds()
	if err != nil {
		t.Fatalf("bad: err: %v", err)
	}

	caData := map[string]interface{}{
		"api_key":      tc.Key,
		"api_secret":   tc.Secret,
		"api_cert":     tc.Cert,
		"api_cert_key": tc.CertKey,
	}

	caReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "config/authn",
		Storage:     storage,
		Data:        caData,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), caReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	assert.NoError(t, err)

	roleData := map[string]interface{}{
		"allow_any_name":     true,
		"enforce_hostnames":  false,
		"allowed_other_sans": "1.3.6.1.4.1.52683;utf8:*",
		"allowed_uri_sans":   "https://test.com/*",
		"ttl":                "2h",
		"key_type":           "ec",
		"key_bits":           256,
	}

	roleReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "roles/testrole",
		Storage:     storage,
		Data:        roleData,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	// create a CSR and key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	uri, _ := url.Parse("https://test.com/test")
	csrReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "foo.bar.com",
		},
		URIs: []*url.URL{uri},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrReq, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(csr) == 0 {
		t.Fatal("generated csr is empty")
	}
	pemCSR := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})))

	issueData := map[string]interface{}{
		"common_name": "Hello World",
		"alt_names":   "test@test.com",
		"uri_sans":    "https://test.com/test/data?q=1",
		"ip_san":      "1.2.3.4",
		"other_sans":  "1.3.6.1.4.1.52683;utf8:Zombie Emergency Response Organization",
		"format":      "pem",
		"csr":         pemCSR,
	}
	issueReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "sign/testrole",
		Storage:     storage,
		Data:        issueData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	listReq := &logical.Request{
		Operation:   logical.ListOperation,
		Path:        "certs",
		Storage:     storage,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	for _, v := range resp.Data["keys"].([]string) {
		getReq := &logical.Request{
			Operation:   logical.ReadOperation,
			Path:        "cert/" + v,
			Storage:     storage,
			ClientToken: "sample",
		}

		resp, err = b.HandleRequest(context.Background(), getReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("bad: err: %v resp: %#v", err, resp)
		}
		getReq = &logical.Request{
			Operation:   logical.UpdateOperation,
			Path:        "revoke",
			Storage:     storage,
			ClientToken: "sample",
			Data: map[string]interface{}{
				"serial_number": v,
			},
		}

		resp, err = b.HandleRequest(context.Background(), getReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("bad: err: %v resp: %#v", err, resp)
		}
	}
}

func TestBackend_SignCert_rsa(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	tc, err := loadAtlasTestCreds()
	if err != nil {
		t.Fatalf("bad: err: %v", err)
	}

	caData := map[string]interface{}{
		"api_key":      tc.Key,
		"api_secret":   tc.Secret,
		"api_cert":     tc.Cert,
		"api_cert_key": tc.CertKey,
	}

	caReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "config/authn",
		Storage:     storage,
		Data:        caData,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), caReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	assert.NoError(t, err)

	roleData := map[string]interface{}{
		"allow_any_name":     true,
		"enforce_hostnames":  false,
		"allowed_other_sans": "1.3.6.1.4.1.52683;utf8:*",
		"ttl":                "2h",
	}

	roleReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "roles/testrole",
		Storage:     storage,
		Data:        roleData,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	// create a CSR and key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "foo.bar.com",
		},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrReq, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(csr) == 0 {
		t.Fatal("generated csr is empty")
	}
	pemCSR := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})))

	issueData := map[string]interface{}{
		"common_name": "Hello World",
		"alt_names":   "test@test.com",
		"uri_sans":    "https://test.com/test/data?q=1",
		"ip_san":      "1.2.3.4",
		"other_sans":  "1.3.6.1.4.1.52683;utf8:Zombie Emergency Response Organization",
		"format":      "pem",
		"csr":         pemCSR,
	}
	issueReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "sign/testrole",
		Storage:     storage,
		Data:        issueData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	listReq := &logical.Request{
		Operation:   logical.ListOperation,
		Path:        "certs",
		Storage:     storage,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	for _, v := range resp.Data["keys"].([]string) {
		getReq := &logical.Request{
			Operation:   logical.ReadOperation,
			Path:        "cert/" + v,
			Storage:     storage,
			ClientToken: "sample",
		}

		resp, err = b.HandleRequest(context.Background(), getReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("bad: err: %v resp: %#v", err, resp)
		}
		getReq = &logical.Request{
			Operation:   logical.UpdateOperation,
			Path:        "revoke",
			Storage:     storage,
			ClientToken: "sample",
			Data: map[string]interface{}{
				"serial_number": v,
			},
		}

		resp, err = b.HandleRequest(context.Background(), getReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("bad: err: %v resp: %#v", err, resp)
		}
	}
}

func TestBackend_RevokePlusTidy_Intermediate(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	roleData := map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"ttl":               "2h",
	}

	roleReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "roles/testrole",
		Storage:     storage,
		Data:        roleData,
		ClientToken: "root",
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	issueData := map[string]interface{}{
		"common_name":        "Hello World",
		"format":             "pem",
		"private_key_format": "pkcs8",
	}
	issueReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "issue/testrole",
		Storage:     storage,
		Data:        issueData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	revReq := func() {
		revokeData := map[string]interface{}{
			"serial_number": resp.Data["serial_number"],
		}
		revokeReq := &logical.Request{
			Operation:   logical.UpdateOperation,
			Path:        "revoke",
			Storage:     storage,
			Data:        revokeData,
			ClientToken: "sample",
		}

		b.HandleRequest(context.Background(), revokeReq)
	}
	revReq()
	revReq()

	tidyData := map[string]interface{}{
		"tidy_cert_store":    true,
		"tidy_revoked_certs": true,
		"safety_buffer":      "1s",
	}
	tidyReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "tidy",
		Storage:     storage,
		Data:        tidyData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), tidyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	revReq()
}
