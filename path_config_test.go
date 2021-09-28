package atlasvault

import (
	"context"
	"testing"

	"github.com/globalsign/atlas-hashicorp-vault/pkg/atlas"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestAtlasVault_Configure(t *testing.T) {
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
}
