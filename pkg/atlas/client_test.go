package atlas

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/crypto/pkcs12"

	"github.com/stretchr/testify/assert"
)

var testKeyLocation = "./testdata/"

// For the Sake Of Example documentation
func NewDefault(c *ClientConfig) (Client, error) {

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
	clientCertFile, err := ioutil.ReadFile(testKeyLocation + "atlas.dev.pfx")
	if err != nil {
		return nil, err
	}
	// WARN: Hard coded dev password
	blocks, err := pkcs12.ToPEM(clientCertFile, "dev")
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the client certificate PKCS12")
	}

	var pemData []byte
	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}
	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return nil, err
	}

	return New(&ClientConfig{
		HVCAUrl:     "https://emea.api.hvca.globalsign.com:8443",
		APIKey:      String(apiOut.User.APIKey),
		APISecret:   String(apiOut.User.APISecret),
		Certificate: &cert,
	})

}

func Test_Client_Login(t *testing.T) {

	if os.Getenv("HVCAURL") == "" {
		t.Skip("requires HVCAURL to be set")
	}
	c, err := NewDefault(nil)
	if err != nil {
		panic(err)
	}

	err = c.Login(context.TODO())
	if err != nil {
		panic(err)
	}
}

func Test_Client_GetPolicy(t *testing.T) {
	if os.Getenv("HVCAURL") == "" {
		t.Skip("requires HVCAURL to be set")
	}
	c, err := NewDefault(nil)
	if err != nil {
		panic(err)
	}

	ctx := context.TODO()

	err = c.Login(ctx)
	if err != nil {
		panic(err)
	}

	p, err := c.GetConfig(ctx)
	if err != nil {
		panic(err)
	}

	spew.Dump(p)
}

func Example() {
	// Load Your client certificate
	cert, err := tls.LoadX509KeyPair("testdata/example-cert.pem", "testdata/example-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Construct your Client.
	client, err := NewDefault(&ClientConfig{
		APIKey:      String("my_atlas_api_key"),
		APISecret:   String("my_atlas_api_secret"),
		Certificate: &cert,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Optional: Call Login Directly, it will be automatically called on all other calls.
	err = client.Login(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleNewDefault() {
	// Load Your client certificate
	cert, err := tls.LoadX509KeyPair("testdata/example-cert.pem", "testdata/example-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Construct your Client.
	client, err := NewDefault(&ClientConfig{
		APIKey:      String("my_atlas_api_key"),
		APISecret:   String("my_atlas_api_secret"),
		Certificate: &cert,
	})
	if err != nil {
		log.Fatal(err)
	}

	_ = client
}

func ExampleClient_GetCert() {
	// Load Your client certificate
	cert, err := tls.LoadX509KeyPair("testdata/example-cert.pem", "testdata/example-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Construct your Client.
	client, err := NewDefault(&ClientConfig{
		APIKey:      String("my_atlas_api_key"),
		APISecret:   String("my_atlas_api_secret"),
		Certificate: &cert,
	})
	if err != nil {
		log.Fatal(err)
	}

	certOut, err := client.GetCert(context.TODO(), "013E636AA765B7A2DF590B794E99443A")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(certOut)
}

func Test_Client_GetTrustChain(t *testing.T) {
	if os.Getenv("HVCAURL") == "" {
		t.Skip("requires HVCAURL to be set")
	}
	c, err := NewDefault(nil)
	if !assert.NoError(t, err) {
		return
	}

	ctx := context.TODO()
	err = c.Login(ctx)
	if !assert.NoError(t, err) {
		return
	}

	p, err := c.GetTrustChain(ctx)
	if !assert.NoError(t, err) {
		return
	}

	// Assume we only have one cert in trust chain for test
	assert.Len(t, p, 1)
}

func Test_Client_GetCert(t *testing.T) {
	if os.Getenv("HVCAURL") == "" {
		t.Skip("requires HVCAURL to be set")
	}
	c, err := NewDefault(nil)
	if !assert.NoError(t, err) {
		return
	}

	ctx := context.TODO()
	err = c.Login(ctx)
	if !assert.NoError(t, err) {
		return
	}

	type GCTest struct {
		Name   string
		ID     string
		Status string
		UAT    uint64
		Error  string
	}

	tests := []*GCTest{
		&GCTest{
			Name:   "Get Known Good",
			ID:     "013E636AA765B7A2DF590B794E99443A",
			Status: "ISSUED",
			UAT:    1605864739,
		},
		&GCTest{
			Name:  "Bad ID Format :",
			ID:    "01:3E:63:6A:A7:65:B7:A2:DF:59:0B:79:4E:99:44:3A",
			Error: "ATLAS-API (422): invalid serial number length",
		},
		&GCTest{
			Name:  "Bad ID Format -",
			ID:    "01-3E-63-6A-A7-65-B7-A2-DF-59-0B-79-4E-99-44-3A",
			Error: "ATLAS-API (422): invalid serial number length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			p, err := c.GetCert(ctx, tt.ID)
			if tt.Error == "" {
				if !assert.NoError(t, err) {
					return
				}
			} else if assert.EqualError(t, err, tt.Error) {
				return
			}

			assert.Equal(t, tt.Status, p.Status)
			assert.Equal(t, tt.UAT, p.UpdatedAt)
		})
	}

}

func ExampleClient_IssueCertificate(t *testing.T) {
	// Load Your client certificate
	cert, err := tls.LoadX509KeyPair("testdata/example-cert.pem", "testdata/example-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	client, err := NewDefault(&ClientConfig{
		APIKey:      String("my_atlas_api_key"),
		APISecret:   String("my_atlas_api_secret"),
		Certificate: &cert,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Make A Key, and CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Lorum Ipsm",
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, pk)
	if err != nil {
		log.Fatal(err)
	}

	// Generate the Request Payload Using Helpers
	req, err := NewIssueCertRequest(csr, &x509.Certificate{
		NotBefore: time.Now().Add(-30 * time.Second),
		NotAfter:  time.Now().Add(30 * time.Minute),
		Subject:   csrTemplate.Subject,
	}, &CertRequestOptions{})
	if err != nil {
		log.Fatal(err)
	}

	outCert, err := client.IssueCertificate(context.TODO(), req)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(outCert)
}
func TestClient_IssueCert(t *testing.T) {
	if os.Getenv("HVCAURL") == "" {
		t.Skip("requires HVCAURL to be set")
	}
	client, err := NewDefault(nil)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.TODO()

	client.Login(ctx)

	type GCTest struct {
		Name    string
		Subject pkix.Name
		Status  string
		Error   string
	}

	tests := []*GCTest{
		&GCTest{
			Name: "Known Good",
			Subject: pkix.Name{
				CommonName: "Lorum Ipsm",
			},
			Status: "ISSUED",
		},
		&GCTest{
			Name: "Outside Of Policy",
			Subject: pkix.Name{
				Country: []string{"Fake"},
			},
			Error: "ATLAS-API (422): subject_dn.common_name: is required",
		},
		&GCTest{
			Name: "Outside of Policy Double",
			Subject: pkix.Name{
				CommonName: "Lorum Ipsm",
				Country:    []string{"Fake", "two"},
			},
			Error: "ATLAS-API (422): subject_dn.country: is static",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			csrTemplate := &x509.CertificateRequest{
				Subject:            tt.Subject,
				SignatureAlgorithm: x509.SHA256WithRSA,
			}
			pk, err := rsa.GenerateKey(rand.Reader, 2048)
			if !assert.NoError(t, err) {
				return
			}

			csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, pk)
			if !assert.NoError(t, err) {
				return
			}

			// Generate the Request Payload Using Helpers
			req, err := NewIssueCertRequest(csr, &x509.Certificate{
				NotBefore: time.Now().Add(-30 * time.Second),
				NotAfter:  time.Now().Add(30 * time.Minute),
				Subject:   tt.Subject,
			}, &CertRequestOptions{})
			if !assert.NoError(t, err) {
				return
			}

			cert, err := client.IssueCertificate(ctx, req)
			if tt.Error == "" {
				if !assert.NoError(t, err) {
					return
				}
			} else if assert.EqualError(t, err, tt.Error) {
				return
			}

			assert.Equal(t, tt.Status, cert.Status)

			block, _ := pem.Decode([]byte(cert.Certificate))
			pcert, err := x509.ParseCertificate(block.Bytes)
			if !assert.NoError(t, err) {
				return
			}

			err = client.RevokeCert(ctx, fmt.Sprintf("%X", pcert.SerialNumber))
			if !assert.NoError(t, err) {
				return
			}
		})
	}
}
