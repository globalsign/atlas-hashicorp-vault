// Package atlasvault integrates GlobalSign Atlas with Hashicorp Vault using the plugin Interface.
package atlasvault

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/globalsign/atlas-hashicorp-vault/pkg/atlas"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory configures and returns the GlobalSign Atlas Vault Plugin Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	var err error
	b := NewBackend(conf, nil)
	if conf != nil && len(conf.Config) != 0 {
		b.issuanceOptions, err = parseIssuanceOptions(conf.Config)
		if err != nil {
			return nil, err
		}
	}
	b.Backend.Setup(ctx, conf)
	return b, nil
}

type atlasConstructor func(*atlas.ClientConfig) (atlas.Client, error)

// Backend returns a new Backend framework struct
func NewBackend(conf *logical.BackendConfig, clientConstructor atlasConstructor) *Backend {
	if clientConstructor == nil {
		clientConstructor = atlas.New
	}
	b := &Backend{
		clientConstructor: clientConstructor,
		tidyCASGuard:      new(uint32),
	}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(atlasHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/authn",
			},
		},

		Secrets: []*framework.Secret{
			secretCerts(b),
		},
	}

	b.Backend.Paths = append(b.Backend.Paths, b.paths()...)
	return b
}

func parseIssuanceOptions(opts map[string]string) (out *atlas.CertRequestOptions, err error) {
	out = &atlas.CertRequestOptions{}
	if v, found := opts["OverrideSignatureAlgorithm"]; found {
		out.OverrideSignatureAlgorithm = &v
	}

	if v, found := opts["OverrideSignatureHashAlgorithm"]; found {
		out.OverrideSignatureHashAlgorithm = &v
	}

	if v, found := opts["OverrideDisableKeyUsageExtensions"]; found {
		out.OverrideDisableKeyUsageExtensions, err = strconv.ParseBool(v)
		if err != nil {
			return nil, errutil.UserError{Err: "Config 'OverrideDisableKeyUsageExtensions': " + err.Error()}
		}
	}
	if v, found := opts["OverrideDisableExtendedKeyUsageExtensions"]; found {
		out.OverrideDisableExtendedKeyUsageExtensions, err = strconv.ParseBool(v)
		if err != nil {
			return nil, errutil.UserError{Err: "Config 'OverrideDisableExtendedKeyUsageExtensions': " + err.Error()}
		}
	}

	return out, nil
}

// Backend wraps the Backend framework and adds a map for storing key value pairs
type Backend struct {
	*framework.Backend

	// cachedAtlasClient should not be used directly, please call the getter method getAtlasClient
	cachedAtlasClient atlas.Client
	clientConstructor atlasConstructor

	// issuanceOptions overrides behavior of x509 cert template to Atlas request on a plugin level.
	issuanceOptions *atlas.CertRequestOptions

	tidyCASGuard *uint32
}

const (

	// storageSystemPrefix is used to store things like module configuration
	storageSystemPrefix = "sys/"

	// Configuration value locations, stored under system prefix.
	storageAtlasAPIKey    = "atlas/api_key"
	storageAtlasAPISecret = "atlas/api_secret"
	storageAtlasAPICert   = "atlas/cert_pem"
)

// getSystemValue gets the vault stored state under the system prefix using the provided logical storage.
func (b *Backend) getSystemValue(ctx context.Context, storage logical.Storage, key string) ([]byte, error) {
	sysVal, err := storage.Get(ctx, storageSystemPrefix+key)
	if err != nil {
		return nil, err
	}
	if sysVal == nil {
		return nil, fmt.Errorf("System Value Not Found '%s'", key)
	}
	return sysVal.Value, nil
}

// setSystemValue persists a value in the provided vault logical storage Backend using the system prefix.
func (b *Backend) setSystemValue(ctx context.Context, storage logical.Storage, key string, value []byte) error {
	return storage.Put(ctx, &logical.StorageEntry{
		Key:      storageSystemPrefix + key,
		Value:    value,
		SealWrap: true,
	})
}

// getAtlasClient gets the cached atlas client or will lazily generate one based on stored paramters.
func (b *Backend) GetAtlasClient(ctx context.Context, storage logical.Storage) (atlas.Client, error) {
	// Check cached version
	if b.cachedAtlasClient != nil {
		return b.cachedAtlasClient, nil
	}

	// Lazy construct using stored paramters
	apiKey, err := b.getSystemValue(ctx, storage, storageAtlasAPIKey)
	if err != nil {
		return nil, err
	}

	apiSecret, err := b.getSystemValue(ctx, storage, storageAtlasAPISecret)
	if err != nil {
		return nil, err
	}

	apiCert, err := b.getSystemValue(ctx, storage, storageAtlasAPICert)
	if err != nil {
		return nil, err
	}

	// Parse the cert into a key pair object
	// Note: Cert value is conjoined blob, this is done for the sake of simplicity
	cert, err := tls.X509KeyPair(apiCert, apiCert)
	if err != nil {
		return nil, err
	}

	HVCAUrl := os.Getenv("HVCAURL")
	if len(HVCAUrl) == 0 {
		HVCAUrl = "https://emea.api.hvca.globalsign.com:8443"
	}

	// Assumption: Constructor will throw error if atlas is misconfigured.
	hclient, err := b.clientConstructor(&atlas.ClientConfig{
		// Cast []byte to *string
		HVCAUrl:     HVCAUrl,
		APIKey:      atlas.String(string(apiKey)),
		APISecret:   atlas.String(string(apiSecret)),
		Certificate: &cert,
	})
	if err != nil {
		return nil, err
	}

	// Make a call with the provided parameters to tie an error to the configuration if necessary.
	if err := hclient.Login(ctx); err != nil {
		return nil, err
	}

	// Set cached version to avoid future reconstruction
	b.cachedAtlasClient = hclient
	return b.cachedAtlasClient, nil
}

func (b *Backend) paths() []*framework.Path {
	return []*framework.Path{
		pathConfigureAuthn(b),
		pathListRoles(b),
		pathRoles(b),

		pathSign(b),
		pathIssue(b),

		pathFetchCA(b),
		pathFetchCAChain(b),

		pathRevoke(b),
		pathFetchValid(b),
		pathFetchListCerts(b),

		pathTidy(b),
	}
}

func (b *Backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	// Invokes storage engine
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

const atlasHelp = `
Atlas enables you to Issue and Manage certificates using your GlobalSign Atlas Instance.
`
