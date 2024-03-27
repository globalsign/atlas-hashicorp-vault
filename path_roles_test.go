package atlasvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	mathrand "math/rand"

	"github.com/fatih/structs"
	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"

	//logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/crypto/cryptobyte"
	cbbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/net/idna"

	"github.com/globalsign/atlas-hashicorp-vault/pkg/atlas"
)

// TestCheckFunc is the callback used for Check in TestStep.
type TestCheckFunc func(*logical.Response) error

// TestCase is a single set of tests to run for a backend. A TestCase
// should generally map 1:1 to each test method for your acceptance
// tests.
type TestCase struct {
	// Precheck, if non-nil, will be called once before the test case
	// runs at all. This can be used for some validation prior to the
	// test running.
	PreCheck func()

	// LogicalBackend is the backend that will be mounted.
	LogicalBackend logical.Backend

	// LogicalFactory can be used instead of LogicalBackend if the
	// backend requires more construction
	LogicalFactory logical.Factory

	// CredentialBackend is the backend that will be mounted.
	CredentialBackend logical.Backend

	// CredentialFactory can be used instead of CredentialBackend if the
	// backend requires more construction
	CredentialFactory logical.Factory

	// Steps are the set of operations that are run for this test case.
	Steps []TestStep

	// Teardown will be called before the test case is over regardless
	// of if the test succeeded or failed. This should return an error
	// in the case that the test can't guarantee all resources were
	// properly cleaned up.
	//Teardown TestTeardownFunc

	// AcceptanceTest, if set, the test case will be run only if
	// the environment variable VAULT_ACC is set. If not this test case
	// will be run as a unit test.
	AcceptanceTest bool
}

// TestStep is a single step within a TestCase.
type TestStep struct {
	// Operation is the operation to execute
	Operation logical.Operation

	// Path is the request path. The mount prefix will be automatically added.
	Path string

	// Arguments to pass in
	Data map[string]interface{}

	// Check is called after this step is executed in order to test that
	// the step executed successfully. If this is not set, then the next
	// step will be called
	Check TestCheckFunc

	// PreFlight is called directly before execution of the request, allowing
	// modification of the request parameters (e.g. Path) with dynamic values.
	//PreFlight PreFlightFunc

	// ErrorOk, if true, will let erroneous responses through to the check
	ErrorOk bool

	// Unauthenticated, if true, will make the request unauthenticated.
	Unauthenticated bool

	// RemoteAddr, if set, will set the remote addr on the request.
	RemoteAddr string

	// ConnState, if set, will set the tls connection state
	//ConnState *tls.ConnectionState
}

var (
	stepCount               = 0
	serialUnderTest         string
	parsedKeyUsageUnderTest int
)

var (
	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
)

// otherNameRaw describes a name related to a certificate which is not in one
// of the standard name formats. RFC 5280, 4.2.1.6:
//
//	OtherName ::= SEQUENCE {
//	     type-id    OBJECT IDENTIFIER,
//	     value      [0] EXPLICIT ANY DEFINED BY type-id }
type otherNameRaw struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue
}

// ExtractUTF8String returns the UTF8 string contained in the Value, or an error
// if none is present.
func (oraw *otherNameRaw) extractUTF8String() (*otherNameUtf8, error) {
	svalue := cryptobyte.String(oraw.Value.Bytes)
	var outTag cbbasn1.Tag
	var val cryptobyte.String
	read := svalue.ReadAnyASN1(&val, &outTag)

	if read && outTag == asn1.TagUTF8String {
		return &otherNameUtf8{oid: oraw.TypeID.String(), value: string(val)}, nil
	}
	return nil, fmt.Errorf("no UTF-8 string found in OtherName")
}

type otherNameUtf8 struct {
	oid   string
	value string
}

func (o otherNameUtf8) String() string {
	return fmt.Sprintf("%s;%s:%s", o.oid, "UTF-8", o.value)
}
func getOtherSANsFromX509Extensions(exts []pkix.Extension) ([]otherNameUtf8, error) {
	var ret []otherNameUtf8
	for _, ext := range exts {
		if !ext.Id.Equal(oidExtensionSubjectAltName) {
			continue
		}
		err := forEachSAN(ext.Value, func(tag int, data []byte) error {
			if tag != 0 {
				return nil
			}

			var other otherNameRaw
			_, err := asn1.UnmarshalWithParams(data, &other, "tag:0")
			if err != nil {
				return fmt.Errorf("could not parse requested other SAN: %v", err)
			}
			val, err := other.extractUTF8String()
			if err != nil {
				return err
			}
			ret = append(ret, *val)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return ret, nil
}

func forEachSAN(extension []byte, callback func(tag int, data []byte) error) error {
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return fmt.Errorf("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v.Tag, v.FullBytes); err != nil {
			return err
		}
	}

	return nil
}

func createBackendWithStorage(t *testing.T, mc *atlas.MockClient) (*Backend, logical.Storage) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	returnMock := func(cc *atlas.ClientConfig) (atlas.Client, error) {

		return mc, nil
	}
	var err error
	b := NewBackend(config, returnMock)
	err = b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	setupAtlasClient(t, b, config.StorageView)

	return b, config.StorageView
}

func setupAtlasClient(t *testing.T, b *Backend, storage logical.Storage) {
	tc, err := loadAtlasTestCreds()
	if err != nil {
		t.Fatalf("bad: err: %v", err)
	}
	authData := map[string]interface{}{
		"api_key":      tc.Key,
		"api_secret":   tc.Secret,
		"api_cert":     tc.Cert,
		"api_cert_key": tc.CertKey,
	}

	authReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "config/authn",
		Storage:     storage,
		Data:        authData,
		ClientToken: "apple",
	}

	resp, err := b.HandleRequest(context.Background(), authReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}
}
func TestAtlasVault_RoleGenerateLease(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	roleData := map[string]interface{}{
		"allowed_domains": "myvault.com",
		"ttl":             "5h",
	}

	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	// generate_lease cannot be nil. It either has to be set during role
	// creation or has to be filled in by the upgrade code
	generateLease := resp.Data["generate_lease"].(*bool)
	if generateLease == nil {
		t.Fatalf("generate_lease should not be nil")
	}

	// By default, generate_lease should be `false`
	if *generateLease {
		t.Fatalf("generate_lease should not be set by default")
	}

	// Update values due to switching of ttl type
	resp.Data["ttl_duration"] = resp.Data["ttl"]
	resp.Data["ttl"] = (time.Duration(resp.Data["ttl"].(int64)) * time.Second).String()
	resp.Data["max_ttl_duration"] = resp.Data["max_ttl"]
	resp.Data["max_ttl"] = (time.Duration(resp.Data["max_ttl"].(int64)) * time.Second).String()
	// role.GenerateLease will be nil after the decode
	var role roleEntry
	err = mapstructure.Decode(resp.Data, &role)
	if err != nil {
		t.Fatal(err)
	}

	// Make it explicit
	role.GenerateLease = nil

	entry, err := logical.StorageEntryJSON("role/testrole", role)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	// Reading should upgrade generate_lease
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	generateLease = resp.Data["generate_lease"].(*bool)
	if generateLease == nil {
		t.Fatalf("generate_lease should not be nil")
	}

	// Upgrade should set generate_lease to `true`
	if !*generateLease {
		t.Fatalf("generate_lease should be set after an upgrade")
	}

	// Make sure that setting generate_lease to `true` works properly
	roleReq.Operation = logical.UpdateOperation
	roleReq.Path = "roles/testrole2"
	roleReq.Data["generate_lease"] = true

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	generateLease = resp.Data["generate_lease"].(*bool)
	if generateLease == nil {
		t.Fatalf("generate_lease should not be nil")
	}
	if !*generateLease {
		t.Fatalf("generate_lease should have been set")
	}
}

func TestAtlasVault_RoleKeyUsage(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	roleData := map[string]interface{}{
		"allowed_domains": "myvault.com",
		"ttl":             "5h",
		"key_usage":       []string{"KeyEncipherment", "DigitalSignature"},
	}

	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	keyUsage := resp.Data["key_usage"].([]string)
	if len(keyUsage) != 2 {
		t.Fatalf("key_usage should have 2 values")
	}

	// Update values due to switching of ttl type
	resp.Data["ttl_duration"] = resp.Data["ttl"]
	resp.Data["ttl"] = (time.Duration(resp.Data["ttl"].(int64)) * time.Second).String()
	resp.Data["max_ttl_duration"] = resp.Data["max_ttl"]
	resp.Data["max_ttl"] = (time.Duration(resp.Data["max_ttl"].(int64)) * time.Second).String()
	// Check that old key usage value is nil
	var role roleEntry
	err = mapstructure.Decode(resp.Data, &role)
	if err != nil {
		t.Fatal(err)
	}
	if role.KeyUsageOld != "" {
		t.Fatalf("old key usage storage value should be blank")
	}

	// Make it explicit
	role.KeyUsageOld = "KeyEncipherment,DigitalSignature"
	role.KeyUsage = nil

	entry, err := logical.StorageEntryJSON("role/testrole", role)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	// Reading should upgrade key_usage
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	keyUsage = resp.Data["key_usage"].([]string)
	if len(keyUsage) != 2 {
		t.Fatalf("key_usage should have 2 values")
	}

	// Read back from storage to ensure upgrade
	entry, err = storage.Get(context.Background(), "role/testrole")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if entry == nil {
		t.Fatalf("role should not be nil")
	}
	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		t.Fatalf("err: %v", err)
	}

	if result.KeyUsageOld != "" {
		t.Fatal("old key usage value should be blank")
	}
	if len(result.KeyUsage) != 2 {
		t.Fatal("key_usage should have 2 values")
	}
}

func TestAtlasVault_RoleOUOrganizationUpgrade(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	roleData := map[string]interface{}{
		"allowed_domains": "myvault.com",
		"ttl":             "5h",
		"ou":              []string{"abc", "123"},
		"organization":    []string{"org1", "org2"},
	}

	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	ou := resp.Data["ou"].([]string)
	if len(ou) != 2 {
		t.Fatalf("ou should have 2 values")
	}
	organization := resp.Data["organization"].([]string)
	if len(organization) != 2 {
		t.Fatalf("organization should have 2 values")
	}

	// Update values due to switching of ttl type
	resp.Data["ttl_duration"] = resp.Data["ttl"]
	resp.Data["ttl"] = (time.Duration(resp.Data["ttl"].(int64)) * time.Second).String()
	resp.Data["max_ttl_duration"] = resp.Data["max_ttl"]
	resp.Data["max_ttl"] = (time.Duration(resp.Data["max_ttl"].(int64)) * time.Second).String()
	// Check that old key usage value is nil
	var role roleEntry
	err = mapstructure.Decode(resp.Data, &role)
	if err != nil {
		t.Fatal(err)
	}
	if role.OUOld != "" {
		t.Fatalf("old ou storage value should be blank")
	}
	if role.OrganizationOld != "" {
		t.Fatalf("old organization storage value should be blank")
	}

	// Make it explicit
	role.OUOld = "abc,123"
	role.OU = nil
	role.OrganizationOld = "org1,org2"
	role.Organization = nil

	entry, err := logical.StorageEntryJSON("role/testrole", role)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	// Reading should upgrade key_usage
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	ou = resp.Data["ou"].([]string)
	if len(ou) != 2 {
		t.Fatalf("ou should have 2 values")
	}
	organization = resp.Data["organization"].([]string)
	if len(organization) != 2 {
		t.Fatalf("organization should have 2 values")
	}

	// Read back from storage to ensure upgrade
	entry, err = storage.Get(context.Background(), "role/testrole")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if entry == nil {
		t.Fatalf("role should not be nil")
	}
	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		t.Fatalf("err: %v", err)
	}

	if result.OUOld != "" {
		t.Fatal("old ou value should be blank")
	}
	if len(result.OU) != 2 {
		t.Fatal("ou should have 2 values")
	}
	if result.OrganizationOld != "" {
		t.Fatal("old organization value should be blank")
	}
	if len(result.Organization) != 2 {
		t.Fatal("organization should have 2 values")
	}
}

func TestAtlasVault_RoleAllowedDomains(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	roleData := map[string]interface{}{
		"allowed_domains": []string{"foobar.com", "*example.com"},
		"ttl":             "5h",
	}

	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	allowedDomains := resp.Data["allowed_domains"].([]string)
	if len(allowedDomains) != 2 {
		t.Fatalf("allowed_domains should have 2 values")
	}

	// Update values due to switching of ttl type
	resp.Data["ttl_duration"] = resp.Data["ttl"]
	resp.Data["ttl"] = (time.Duration(resp.Data["ttl"].(int64)) * time.Second).String()
	resp.Data["max_ttl_duration"] = resp.Data["max_ttl"]
	resp.Data["max_ttl"] = (time.Duration(resp.Data["max_ttl"].(int64)) * time.Second).String()
	// Check that old key usage value is nil
	var role roleEntry
	err = mapstructure.Decode(resp.Data, &role)
	if err != nil {
		t.Fatal(err)
	}
	if role.AllowedDomainsOld != "" {
		t.Fatalf("old allowed_domains storage value should be blank")
	}

	// Make it explicit
	role.AllowedDomainsOld = "foobar.com,*example.com"
	role.AllowedDomains = nil

	entry, err := logical.StorageEntryJSON("role/testrole", role)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	// Reading should upgrade key_usage
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	allowedDomains = resp.Data["allowed_domains"].([]string)
	if len(allowedDomains) != 2 {
		t.Fatalf("allowed_domains should have 2 values")
	}

	// Read back from storage to ensure upgrade
	entry, err = storage.Get(context.Background(), "role/testrole")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if entry == nil {
		t.Fatalf("role should not be nil")
	}
	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		t.Fatalf("err: %v", err)
	}

	if result.AllowedDomainsOld != "" {
		t.Fatal("old allowed_domains value should be blank")
	}
	if len(result.AllowedDomains) != 2 {
		t.Fatal("allowed_domains should have 2 values")
	}
}

func TestAtlasVault_RoleAllowedURISANs(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	roleData := map[string]interface{}{
		"allowed_uri_sans": []string{"http://foobar.com", "spiffe://*"},
		"ttl":              "5h",
	}

	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	allowedURISANs := resp.Data["allowed_uri_sans"].([]string)
	if len(allowedURISANs) != 2 {
		t.Fatalf("allowed_uri_sans should have 2 values")
	}
}

func TestAtlasVault_RoleAtlasVaultxFields(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	roleData := map[string]interface{}{
		"ttl":            "5h",
		"country":        []string{"c1", "c2"},
		"ou":             []string{"abc", "123"},
		"organization":   []string{"org1", "org2"},
		"locality":       []string{"foocity", "bartown"},
		"province":       []string{"bar", "foo"},
		"street_address": []string{"123 foo street", "789 bar avenue"},
		"postal_code":    []string{"f00", "b4r"},
	}

	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/testrole_atlasvaultxfields",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	origCountry := roleData["country"].([]string)
	respCountry := resp.Data["country"].([]string)
	if !strutil.StrListSubset(origCountry, respCountry) {
		t.Fatalf("country did not match values set in role")
	} else if len(origCountry) != len(respCountry) {
		t.Fatalf("country did not have same number of values set in role")
	}

	origOU := roleData["ou"].([]string)
	respOU := resp.Data["ou"].([]string)
	if !strutil.StrListSubset(origOU, respOU) {
		t.Fatalf("ou did not match values set in role")
	} else if len(origOU) != len(respOU) {
		t.Fatalf("ou did not have same number of values set in role")
	}

	origOrganization := roleData["organization"].([]string)
	respOrganization := resp.Data["organization"].([]string)
	if !strutil.StrListSubset(origOrganization, respOrganization) {
		t.Fatalf("organization did not match values set in role")
	} else if len(origOrganization) != len(respOrganization) {
		t.Fatalf("organization did not have same number of values set in role")
	}

	origLocality := roleData["locality"].([]string)
	respLocality := resp.Data["locality"].([]string)
	if !strutil.StrListSubset(origLocality, respLocality) {
		t.Fatalf("locality did not match values set in role")
	} else if len(origLocality) != len(respLocality) {
		t.Fatalf("locality did not have same number of values set in role: ")
	}

	origProvince := roleData["province"].([]string)
	respProvince := resp.Data["province"].([]string)
	if !strutil.StrListSubset(origProvince, respProvince) {
		t.Fatalf("province did not match values set in role")
	} else if len(origProvince) != len(respProvince) {
		t.Fatalf("province did not have same number of values set in role")
	}

	origStreetAddress := roleData["street_address"].([]string)
	respStreetAddress := resp.Data["street_address"].([]string)
	if !strutil.StrListSubset(origStreetAddress, respStreetAddress) {
		t.Fatalf("street_address did not match values set in role")
	} else if len(origStreetAddress) != len(respStreetAddress) {
		t.Fatalf("street_address did not have same number of values set in role")
	}

	origPostalCode := roleData["postal_code"].([]string)
	respPostalCode := resp.Data["postal_code"].([]string)
	if !strutil.StrListSubset(origPostalCode, respPostalCode) {
		t.Fatalf("postal_code did not match values set in role")
	} else if len(origPostalCode) != len(respPostalCode) {
		t.Fatalf("postal_code did not have same number of values set in role")
	}
}

type TestCreds struct {
	Key     string
	Secret  string
	Cert    string
	CertKey string
}

func TestAtlasVault_CertsLease(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &atlas.MockClient{})

	roleData := map[string]interface{}{
		"allowed_domains":  "myvault.com",
		"allow_subdomains": true,
		"ttl":              "2h",
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
		"common_name": "cert.myvault.com",
		"format":      "pem",
		"ip_sans":     "127.0.0.1",
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

	if resp.Secret != nil {
		t.Fatalf("expected a response that does not contain a secret")
	}

	// Turn on the lease generation and issue a certificate. The response
	// should have a `Secret` object populated.
	roleData["generate_lease"] = true

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	if resp.Secret == nil {
		t.Fatalf("expected a response that contains a secret")
	}
}

// Generates and tests steps that walk through the various possibilities
// of role flags to ensure that they are properly restricted
func TestBackend_Roles(t *testing.T) {
	cases := []struct {
		name      string
		key, cert *string
		useCSR    bool
	}{
		{"RSA", &rsaCAKey, &rsaCACert, false},
		// {"RSACSR", &rsaCAKey, &rsaCACert, true},
		// {"EC", &ecCAKey, &ecCACert, false},
		// {"ECCSR", &ecCAKey, &ecCACert, true},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			initTest.Do(setCerts)
			b, storage := createBackendWithStorage(t, &atlas.MockClient{})

			testCase := TestCase{
				LogicalBackend: b,
				Steps:          []TestStep{},
			}

			testCase.Steps = append(testCase.Steps, generateRoleSteps(t, tc.useCSR)...)
			if len(os.Getenv("VAULT_VERBOSE_PKITESTS")) > 0 {
				for i, v := range testCase.Steps {
					data := map[string]interface{}{}
					var keys []string
					for k := range v.Data {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						interf := v.Data[k]
						switch v := interf.(type) {
						case bool:
							if !v {
								continue
							}
						case int:
							if v == 0 {
								continue
							}
						case []string:
							if len(v) == 0 {
								continue
							}
						case string:
							if v == "" {
								continue
							}
							lines := strings.Split(v, "\n")
							if len(lines) > 1 {
								data[k] = lines[0] + " ... (truncated)"
								continue
							}
						}
						data[k] = interf

					}
					t.Logf("Step %d:\n%s %s err=%v %+v\n\n", i+1, v.Operation, v.Path, v.ErrorOk, data)
				}
			}

			for _, step := range testCase.Steps {
				roleReq := &logical.Request{
					Operation:   step.Operation,
					Path:        step.Path,
					Storage:     storage,
					Data:        step.Data,
					ClientToken: "root",
				}

				resp, _ := b.HandleRequest(context.Background(), roleReq)
				if step.Check != nil {
					step.Check(resp)
				}
			}

			//logicaltest.Test(t, testCase)
		})
	}
}

// Generates steps to test out various role permutations
func generateRoleSteps(t *testing.T, useCSRs bool) []TestStep {
	roleVals := roleEntry{
		MaxTTL:    12 * time.Hour,
		KeyType:   "rsa",
		KeyBits:   2048,
		RequireCN: true,
	}
	issueVals := certutil.IssueData{}
	ret := []TestStep{}

	roleTestStep := TestStep{
		Operation: logical.UpdateOperation,
		Path:      "roles/test",
	}
	var issueTestStep TestStep
	if useCSRs {
		issueTestStep = TestStep{
			Operation: logical.UpdateOperation,
			Path:      "sign/test",
		}
	} else {
		issueTestStep = TestStep{
			Operation: logical.UpdateOperation,
			Path:      "issue/test",
		}
	}

	generatedRSAKeys := map[int]crypto.Signer{}
	generatedECKeys := map[int]crypto.Signer{}

	/*
		// For the number of tests being run, a seed of 1 has been tested
		// to hit all of the various values below. However, for normal
		// testing we use a randomized time for maximum fuzziness.
	*/
	var seed int64 = 1
	fixedSeed := os.Getenv("VAULT_PKITESTS_FIXED_SEED")
	if len(fixedSeed) == 0 {
		seed = time.Now().UnixNano()
	} else {
		var err error
		seed, err = strconv.ParseInt(fixedSeed, 10, 64)
		if err != nil {
			t.Fatalf("error parsing fixed seed of %s: %v", fixedSeed, err)
		}
	}
	mathRand := mathrand.New(mathrand.NewSource(seed))
	// t.Logf("seed under test: %v", seed)

	// Used by tests not toggling common names to turn off the behavior of random key bit fuzziness
	keybitSizeRandOff := false

	genericErrorOkCheck := func(resp *logical.Response) error {
		if resp.IsError() {
			return nil
		}
		return fmt.Errorf("expected an error, but did not seem to get one")
	}

	// Adds tests with the currently configured issue/role information
	addTests := func(testCheck TestCheckFunc) {
		stepCount++
		//t.Logf("test step %d\nrole vals: %#v\n", stepCount, roleVals)
		stepCount++
		//t.Logf("test step %d\nissue vals: %#v\n", stepCount, issueTestStep)
		roleTestStep.Data = roleVals.ToResponseData()
		roleTestStep.Data["generate_lease"] = false
		ret = append(ret, roleTestStep)
		issueTestStep.Data = structs.New(issueVals).Map()
		switch {
		case issueTestStep.ErrorOk:
			issueTestStep.Check = genericErrorOkCheck
		case testCheck != nil:
			issueTestStep.Check = testCheck
		default:
			issueTestStep.Check = nil
		}
		ret = append(ret, issueTestStep)
	}

	getCountryCheck := func(role roleEntry) TestCheckFunc {
		var certBundle certutil.CertBundle
		return func(resp *logical.Response) error {
			err := mapstructure.Decode(resp.Data, &certBundle)
			if err != nil {
				return err
			}
			parsedCertBundle, err := certBundle.ToParsedCertBundle()
			if err != nil {
				return fmt.Errorf("error checking generated certificate: %s", err)
			}
			cert := parsedCertBundle.Certificate

			expected := strutil.RemoveDuplicates(role.Country, true)
			if !reflect.DeepEqual(cert.Subject.Country, expected) {
				return fmt.Errorf("error: returned certificate has Country of %s but %s was specified in the role", cert.Subject.Country, expected)
			}
			return nil
		}
	}

	getOuCheck := func(role roleEntry) TestCheckFunc {
		var certBundle certutil.CertBundle
		return func(resp *logical.Response) error {
			err := mapstructure.Decode(resp.Data, &certBundle)
			if err != nil {
				return err
			}
			parsedCertBundle, err := certBundle.ToParsedCertBundle()
			if err != nil {
				return fmt.Errorf("error checking generated certificate: %s", err)
			}
			cert := parsedCertBundle.Certificate

			expected := strutil.RemoveDuplicatesStable(role.OU, true)
			if !reflect.DeepEqual(cert.Subject.OrganizationalUnit, expected) {
				return fmt.Errorf("error: returned certificate has OU of %s but %s was specified in the role", cert.Subject.OrganizationalUnit, expected)
			}
			return nil
		}
	}

	getOrganizationCheck := func(role roleEntry) TestCheckFunc {
		var certBundle certutil.CertBundle
		return func(resp *logical.Response) error {
			err := mapstructure.Decode(resp.Data, &certBundle)
			if err != nil {
				return err
			}
			parsedCertBundle, err := certBundle.ToParsedCertBundle()
			if err != nil {
				return fmt.Errorf("error checking generated certificate: %s", err)
			}
			cert := parsedCertBundle.Certificate

			expected := strutil.RemoveDuplicates(role.Organization, true)
			if !reflect.DeepEqual(cert.Subject.Organization, expected) {
				return fmt.Errorf("error: returned certificate has Organization of %s but %s was specified in the role", cert.Subject.Organization, expected)
			}
			return nil
		}
	}

	getLocalityCheck := func(role roleEntry) TestCheckFunc {
		var certBundle certutil.CertBundle
		return func(resp *logical.Response) error {
			err := mapstructure.Decode(resp.Data, &certBundle)
			if err != nil {
				return err
			}
			parsedCertBundle, err := certBundle.ToParsedCertBundle()
			if err != nil {
				return fmt.Errorf("error checking generated certificate: %s", err)
			}
			cert := parsedCertBundle.Certificate

			expected := strutil.RemoveDuplicates(role.Locality, true)
			if !reflect.DeepEqual(cert.Subject.Locality, expected) {
				return fmt.Errorf("error: returned certificate has Locality of %s but %s was specified in the role", cert.Subject.Locality, expected)
			}
			return nil
		}
	}

	getProvinceCheck := func(role roleEntry) TestCheckFunc {
		var certBundle certutil.CertBundle
		return func(resp *logical.Response) error {
			err := mapstructure.Decode(resp.Data, &certBundle)
			if err != nil {
				return err
			}
			parsedCertBundle, err := certBundle.ToParsedCertBundle()
			if err != nil {
				return fmt.Errorf("error checking generated certificate: %s", err)
			}
			cert := parsedCertBundle.Certificate

			expected := strutil.RemoveDuplicates(role.Province, true)
			if !reflect.DeepEqual(cert.Subject.Province, expected) {
				return fmt.Errorf("error: returned certificate has Province of %s but %s was specified in the role", cert.Subject.Province, expected)
			}
			return nil
		}
	}

	getStreetAddressCheck := func(role roleEntry) TestCheckFunc {
		var certBundle certutil.CertBundle
		return func(resp *logical.Response) error {
			err := mapstructure.Decode(resp.Data, &certBundle)
			if err != nil {
				return err
			}
			parsedCertBundle, err := certBundle.ToParsedCertBundle()
			if err != nil {
				return fmt.Errorf("error checking generated certificate: %s", err)
			}
			cert := parsedCertBundle.Certificate

			expected := strutil.RemoveDuplicates(role.StreetAddress, true)
			if !reflect.DeepEqual(cert.Subject.StreetAddress, expected) {
				return fmt.Errorf("error: returned certificate has StreetAddress of %s but %s was specified in the role", cert.Subject.StreetAddress, expected)
			}
			return nil
		}
	}

	getPostalCodeCheck := func(role roleEntry) TestCheckFunc {
		var certBundle certutil.CertBundle
		return func(resp *logical.Response) error {
			err := mapstructure.Decode(resp.Data, &certBundle)
			if err != nil {
				return err
			}
			parsedCertBundle, err := certBundle.ToParsedCertBundle()
			if err != nil {
				return fmt.Errorf("error checking generated certificate: %s", err)
			}
			cert := parsedCertBundle.Certificate

			expected := strutil.RemoveDuplicates(role.PostalCode, true)
			if !reflect.DeepEqual(cert.Subject.PostalCode, expected) {
				return fmt.Errorf("error: returned certificate has PostalCode of %s but %s was specified in the role", cert.Subject.PostalCode, expected)
			}
			return nil
		}
	}

	// Returns a TestCheckFunc that performs various validity checks on the
	// returned certificate information, mostly within checkCertsAndPrivateKey
	getCnCheck := func(name string, role roleEntry, key crypto.Signer, usage x509.KeyUsage, extUsage x509.ExtKeyUsage, validity time.Duration) TestCheckFunc {
		var certBundle certutil.CertBundle
		return func(resp *logical.Response) error {
			err := mapstructure.Decode(resp.Data, &certBundle)
			if err != nil {
				return err
			}
			parsedCertBundle, err := checkCertsAndPrivateKey(role.KeyType, key, usage, extUsage, validity, &certBundle)
			if err != nil {
				return fmt.Errorf("error checking generated certificate: %s", err)
			}
			cert := parsedCertBundle.Certificate
			if cert.Subject.CommonName != name {
				return fmt.Errorf("error: returned certificate has CN of %s but %s was requested", cert.Subject.CommonName, name)
			}
			if strings.Contains(cert.Subject.CommonName, "@") {
				if len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 1 {
					return fmt.Errorf("error: found more than one DNS SAN or not one Email SAN but only one was requested, cert.DNSNames = %#v, cert.EmailAddresses = %#v", cert.DNSNames, cert.EmailAddresses)
				}
			} else {
				if len(cert.DNSNames) != 1 || len(cert.EmailAddresses) != 0 {
					return fmt.Errorf("error: found more than one Email SAN or not one DNS SAN but only one was requested, cert.DNSNames = %#v, cert.EmailAddresses = %#v", cert.DNSNames, cert.EmailAddresses)
				}
			}
			var retName string
			if len(cert.DNSNames) > 0 {
				retName = cert.DNSNames[0]
			}
			if len(cert.EmailAddresses) > 0 {
				retName = cert.EmailAddresses[0]
			}
			if retName != name {
				// Check IDNA
				p := idna.New(
					idna.StrictDomainName(true),
					idna.VerifyDNSLength(true),
				)
				converted, err := p.ToUnicode(retName)
				if err != nil {
					t.Fatal(err)
				}
				if converted != name {
					return fmt.Errorf("error: returned certificate has a DNS SAN of %s (from idna: %s) but %s was requested", retName, converted, name)
				}
			}
			return nil
		}
	}

	type csrPlan struct {
		errorOk     bool
		roleKeyBits int
		cert        string
		privKey     crypto.Signer
	}

	getCsr := func(keyType string, keyBits int, csrTemplate *x509.CertificateRequest) (*pem.Block, crypto.Signer) {
		var privKey crypto.Signer
		var ok bool
		switch keyType {
		case "rsa":
			privKey, ok = generatedRSAKeys[keyBits]
			if !ok {
				privKey, _ = rsa.GenerateKey(rand.Reader, keyBits)
				generatedRSAKeys[keyBits] = privKey
			}

		case "ec":
			var curve elliptic.Curve

			switch keyBits {
			case 224:
				curve = elliptic.P224()
			case 256:
				curve = elliptic.P256()
			case 384:
				curve = elliptic.P384()
			case 521:
				curve = elliptic.P521()
			}

			privKey, ok = generatedECKeys[keyBits]
			if !ok {
				privKey, _ = ecdsa.GenerateKey(curve, rand.Reader)
				generatedECKeys[keyBits] = privKey
			}

		default:
			panic("invalid key type: " + keyType)
		}

		csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
		if err != nil {
			t.Fatalf("Error creating certificate request: %s", err)
		}
		block := pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csr,
		}
		return &block, privKey
	}

	getRandCsr := func(keyType string, errorOk bool, csrTemplate *x509.CertificateRequest) csrPlan {
		rsaKeyBits := []int{2048, 4096}
		ecKeyBits := []int{224, 256, 384, 521}
		var plan = csrPlan{errorOk: errorOk}

		var testBitSize int
		switch keyType {
		case "rsa":
			plan.roleKeyBits = rsaKeyBits[mathRand.Int()%2]
			testBitSize = plan.roleKeyBits

			// If we don't expect an error already, randomly choose a
			// key size and expect an error if it's less than the role
			// setting
			if !keybitSizeRandOff && !errorOk {
				testBitSize = rsaKeyBits[mathRand.Int()%2]
			}

			if testBitSize < plan.roleKeyBits {
				plan.errorOk = true
			}

		case "ec":
			plan.roleKeyBits = ecKeyBits[mathRand.Int()%4]
			testBitSize = plan.roleKeyBits

			// If we don't expect an error already, randomly choose a
			// key size and expect an error if it's less than the role
			// setting
			if !keybitSizeRandOff && !errorOk {
				testBitSize = ecKeyBits[mathRand.Int()%4]
			}

			if testBitSize < plan.roleKeyBits {
				plan.errorOk = true
			}

		default:
			panic("invalid key type: " + keyType)
		}
		if len(os.Getenv("VAULT_VERBOSE_PKITESTS")) > 0 {
			t.Logf("roleKeyBits=%d testBitSize=%d errorOk=%v", plan.roleKeyBits, testBitSize, plan.errorOk)
		}

		block, privKey := getCsr(keyType, testBitSize, csrTemplate)
		plan.cert = strings.TrimSpace(string(pem.EncodeToMemory(block)))
		plan.privKey = privKey
		return plan
	}

	// Common names to test with the various role flags toggled
	var commonNames struct {
		Localhost            bool `structs:"localhost"`
		BareDomain           bool `structs:"example.com"`
		SecondDomain         bool `structs:"foobar.com"`
		SubDomain            bool `structs:"foo.example.com"`
		Wildcard             bool `structs:"*.example.com"`
		SubSubdomain         bool `structs:"foo.bar.example.com"`
		SubSubdomainWildcard bool `structs:"*.bar.example.com"`
		GlobDomain           bool `structs:"fooexample.com"`
		IDN                  bool `structs:"daɪˈɛrɨsɨs"`
		AnyHost              bool `structs:"porkslap.beer"`
	}

	// Adds a series of tests based on the current selection of
	// allowed common names; contains some (seeded) randomness
	//
	// This allows for a variety of common names to be tested in various
	// combinations with allowed toggles of the role
	addCnTests := func() {
		cnMap := structs.New(commonNames).Map()
		for name, allowedInt := range cnMap {
			roleVals.KeyType = "rsa"
			roleVals.KeyBits = 2048
			if mathRand.Int()%2 == 1 {
				roleVals.KeyType = "ec"
				roleVals.KeyBits = 224
			}

			roleVals.ServerFlag = false
			roleVals.ClientFlag = false
			roleVals.CodeSigningFlag = false
			roleVals.EmailProtectionFlag = false

			var usage []string
			if mathRand.Int()%2 == 1 {
				usage = append(usage, "DigitalSignature")
			}
			if mathRand.Int()%2 == 1 {
				usage = append(usage, "ContentCoMmitment")
			}
			if mathRand.Int()%2 == 1 {
				usage = append(usage, "KeyEncipherment")
			}
			if mathRand.Int()%2 == 1 {
				usage = append(usage, "DataEncipherment")
			}
			if mathRand.Int()%2 == 1 {
				usage = append(usage, "KeyAgreemEnt")
			}
			if mathRand.Int()%2 == 1 {
				usage = append(usage, "CertSign")
			}
			if mathRand.Int()%2 == 1 {
				usage = append(usage, "CRLSign")
			}
			if mathRand.Int()%2 == 1 {
				usage = append(usage, "EncipherOnly")
			}
			if mathRand.Int()%2 == 1 {
				usage = append(usage, "DecipherOnly")
			}

			roleVals.KeyUsage = usage
			parsedKeyUsage := parseKeyUsages(roleVals.KeyUsage)
			if parsedKeyUsage == 0 && len(usage) != 0 {
				panic("parsed key usages was zero")
			}
			parsedKeyUsageUnderTest = parsedKeyUsage

			var extUsage x509.ExtKeyUsage
			i := mathRand.Int() % 4
			switch {
			case i == 0:
				// Punt on this for now since I'm not clear the actual proper
				// way to format these
				if name != "daɪˈɛrɨsɨs" {
					extUsage = x509.ExtKeyUsageEmailProtection
					roleVals.EmailProtectionFlag = true
					break
				}
				fallthrough
			case i == 1:
				extUsage = x509.ExtKeyUsageServerAuth
				roleVals.ServerFlag = true
			case i == 2:
				extUsage = x509.ExtKeyUsageClientAuth
				roleVals.ClientFlag = true
			default:
				extUsage = x509.ExtKeyUsageCodeSigning
				roleVals.CodeSigningFlag = true
			}

			allowed := allowedInt.(bool)
			issueVals.CommonName = name
			if roleVals.EmailProtectionFlag {
				if !strings.HasPrefix(name, "*") {
					issueVals.CommonName = "user@" + issueVals.CommonName
				}
			}

			issueTestStep.ErrorOk = !allowed

			validity := roleVals.MaxTTL

			if useCSRs {
				templ := &x509.CertificateRequest{
					Subject: pkix.Name{
						CommonName: issueVals.CommonName,
					},
				}
				plan := getRandCsr(roleVals.KeyType, issueTestStep.ErrorOk, templ)
				issueVals.CSR = plan.cert
				roleVals.KeyBits = plan.roleKeyBits
				issueTestStep.ErrorOk = plan.errorOk

				addTests(getCnCheck(issueVals.CommonName, roleVals, plan.privKey, x509.KeyUsage(parsedKeyUsage), extUsage, validity))
			} else {
				addTests(getCnCheck(issueVals.CommonName, roleVals, nil, x509.KeyUsage(parsedKeyUsage), extUsage, validity))
			}
		}
	}

	funcs := []interface{}{addCnTests, getCnCheck, getCountryCheck, getLocalityCheck,
		getOrganizationCheck, getOuCheck, getPostalCodeCheck, getRandCsr, getStreetAddressCheck,
		getProvinceCheck}
	if len(os.Getenv("VAULT_VERBOSE_PKITESTS")) > 0 {
		t.Logf("funcs=%d", len(funcs))
	}

	// Common Name tests
	{
		// common_name not provided
		issueVals.CommonName = ""
		issueTestStep.ErrorOk = true
		addTests(nil)

		// Nothing is allowed
		addCnTests()

		roleVals.AllowLocalhost = true
		commonNames.Localhost = true
		addCnTests()

		roleVals.AllowedDomains = []string{"foobar.com"}
		addCnTests()

		roleVals.AllowedDomains = []string{"example.com"}
		roleVals.AllowSubdomains = true
		commonNames.SubDomain = true
		commonNames.Wildcard = true
		commonNames.SubSubdomain = true
		commonNames.SubSubdomainWildcard = true
		addCnTests()

		roleVals.AllowedDomains = []string{"foobar.com", "example.com"}
		commonNames.SecondDomain = true
		roleVals.AllowBareDomains = true
		commonNames.BareDomain = true
		addCnTests()

		roleVals.AllowedDomains = []string{"foobar.com", "*example.com"}
		roleVals.AllowGlobDomains = true
		commonNames.GlobDomain = true
		addCnTests()

		roleVals.AllowAnyName = true
		roleVals.EnforceHostnames = true
		commonNames.AnyHost = true
		commonNames.IDN = true
		addCnTests()

		roleVals.EnforceHostnames = false
		addCnTests()

		// Ensure that we end up with acceptable key sizes since they won't be
		// toggled any longer
		keybitSizeRandOff = true
		addCnTests()
	}
	// Country tests
	{
		roleVals.Country = []string{"foo"}
		addTests(getCountryCheck(roleVals))

		roleVals.Country = []string{"foo", "bar"}
		addTests(getCountryCheck(roleVals))
	}
	// OU tests
	{
		roleVals.OU = []string{"foo"}
		addTests(getOuCheck(roleVals))

		roleVals.OU = []string{"bar", "foo"}
		addTests(getOuCheck(roleVals))
	}
	// Organization tests
	{
		roleVals.Organization = []string{"system:masters"}
		addTests(getOrganizationCheck(roleVals))

		roleVals.Organization = []string{"foo", "bar"}
		addTests(getOrganizationCheck(roleVals))
	}
	// Locality tests
	{
		roleVals.Locality = []string{"foo"}
		addTests(getLocalityCheck(roleVals))

		roleVals.Locality = []string{"foo", "bar"}
		addTests(getLocalityCheck(roleVals))
	}
	// Province tests
	{
		roleVals.Province = []string{"foo"}
		addTests(getProvinceCheck(roleVals))

		roleVals.Province = []string{"foo", "bar"}
		addTests(getProvinceCheck(roleVals))
	}
	// StreetAddress tests
	{
		roleVals.StreetAddress = []string{"123 foo street"}
		addTests(getStreetAddressCheck(roleVals))

		roleVals.StreetAddress = []string{"123 foo street", "456 bar avenue"}
		addTests(getStreetAddressCheck(roleVals))
	}
	// PostalCode tests
	{
		roleVals.PostalCode = []string{"f00"}
		addTests(getPostalCodeCheck(roleVals))

		roleVals.PostalCode = []string{"f00", "b4r"}
		addTests(getPostalCodeCheck(roleVals))
	}

	// IP SAN tests
	{
		getIpCheck := func(expectedIp ...net.IP) TestCheckFunc {
			return func(resp *logical.Response) error {
				var certBundle certutil.CertBundle
				err := mapstructure.Decode(resp.Data, &certBundle)
				if err != nil {
					return err
				}
				parsedCertBundle, err := certBundle.ToParsedCertBundle()
				if err != nil {
					return fmt.Errorf("error parsing cert bundle: %s", err)
				}
				cert := parsedCertBundle.Certificate
				var emptyIPs []net.IP
				var expected []net.IP = append(emptyIPs, expectedIp...)
				if diff := deep.Equal(cert.IPAddresses, expected); len(diff) > 0 {
					return fmt.Errorf("wrong SAN IPs, diff: %v", diff)
				}
				return nil
			}
		}
		addIPSANTests := func(useCSRs, useCSRSANs, allowIPSANs, errorOk bool, ipSANs string, csrIPSANs []net.IP, check TestCheckFunc) {
			if useCSRs {
				csrTemplate := &x509.CertificateRequest{
					Subject: pkix.Name{
						CommonName: issueVals.CommonName,
					},
					IPAddresses: csrIPSANs,
				}
				block, _ := getCsr(roleVals.KeyType, roleVals.KeyBits, csrTemplate)
				issueVals.CSR = strings.TrimSpace(string(pem.EncodeToMemory(block)))
			}
			oldRoleVals, oldIssueVals, oldIssueTestStep := roleVals, issueVals, issueTestStep
			roleVals.UseCSRSANs = useCSRSANs
			roleVals.AllowIPSANs = allowIPSANs
			issueVals.CommonName = "someone@example.com"
			issueVals.IPSANs = ipSANs
			issueTestStep.ErrorOk = errorOk
			addTests(check)
			roleVals, issueVals, issueTestStep = oldRoleVals, oldIssueVals, oldIssueTestStep
		}
		roleVals.AllowAnyName = true
		roleVals.EnforceHostnames = true
		roleVals.AllowLocalhost = true
		roleVals.UseCSRCommonName = true
		commonNames.Localhost = true

		netip1, netip2 := net.IP{127, 0, 0, 1}, net.IP{170, 171, 172, 173}
		textip1, textip3 := "127.0.0.1", "::1"

		// IPSANs not allowed and not provided, should not be an error.
		addIPSANTests(useCSRs, false, false, false, "", nil, getIpCheck())

		// IPSANs not allowed, valid IPSANs provided, should be an error.
		addIPSANTests(useCSRs, false, false, true, textip1+","+textip3, nil, nil)

		// IPSANs allowed, bogus IPSANs provided, should be an error.
		addIPSANTests(useCSRs, false, true, true, "foobar", nil, nil)

		// Given IPSANs as API argument and useCSRSANs false, CSR arg ignored.
		addIPSANTests(useCSRs, false, true, false, textip1,
			[]net.IP{netip2}, getIpCheck(netip1))

		if useCSRs {
			// IPSANs not allowed, valid IPSANs provided via CSR, should be an error.
			addIPSANTests(useCSRs, true, false, true, "", []net.IP{netip1}, nil)

			// Given IPSANs as both API and CSR arguments and useCSRSANs=true, API arg ignored.
			addIPSANTests(useCSRs, true, true, false, textip3,
				[]net.IP{netip1, netip2}, getIpCheck(netip1, netip2))
		}
	}

	{

		addOtherSANTests := func(useCSRs, useCSRSANs bool, allowedOtherSANs []string, errorOk bool, otherSANs []string, csrOtherSANs []otherNameUtf8, check TestCheckFunc) {
			otherSansMap := func(os []otherNameUtf8) map[string][]string {
				ret := make(map[string][]string)
				for _, o := range os {
					ret[o.oid] = append(ret[o.oid], o.value)
				}
				return ret
			}
			if useCSRs {
				csrTemplate := &x509.CertificateRequest{
					Subject: pkix.Name{
						CommonName: issueVals.CommonName,
					},
				}
				if err := handleOtherCSRSANs(csrTemplate, otherSansMap(csrOtherSANs)); err != nil {
					t.Fatal(err)
				}
				block, _ := getCsr(roleVals.KeyType, roleVals.KeyBits, csrTemplate)
				issueVals.CSR = strings.TrimSpace(string(pem.EncodeToMemory(block)))
			}
			oldRoleVals, oldIssueVals, oldIssueTestStep := roleVals, issueVals, issueTestStep
			roleVals.UseCSRSANs = useCSRSANs
			roleVals.AllowedOtherSANs = allowedOtherSANs
			issueVals.CommonName = "someone@example.com"
			issueVals.OtherSANs = strings.Join(otherSANs, ",")
			issueTestStep.ErrorOk = errorOk
			addTests(check)
			roleVals, issueVals, issueTestStep = oldRoleVals, oldIssueVals, oldIssueTestStep
		}
		roleVals.AllowAnyName = true
		roleVals.EnforceHostnames = true
		roleVals.AllowLocalhost = true
		roleVals.UseCSRCommonName = true
		commonNames.Localhost = true

		newOtherNameUtf8 := func(s string) (ret otherNameUtf8) {
			pieces := strings.Split(s, ";")
			if len(pieces) == 2 {
				piecesRest := strings.Split(pieces[1], ":")
				if len(piecesRest) == 2 {
					switch strings.ToUpper(piecesRest[0]) {
					case "UTF-8", "UTF8":
						return otherNameUtf8{oid: pieces[0], value: piecesRest[1]}
					}
				}
			}
			t.Fatalf("error parsing otherName: %q", s)
			return
		}
		oid1 := "1.3.6.1.4.1.311.20.2.3"
		oth1str := oid1 + ";utf8:devops@nope.com"
		oth1 := newOtherNameUtf8(oth1str)
		// allowNone, allowAll := []string{}, []string{oid1 + ";UTF-8:*"}
		allowNone, allowAll := []string{}, []string{"*"}

		// OtherSANs not allowed, valid OtherSANs provided, should be an error.
		addOtherSANTests(useCSRs, false, allowNone, true, []string{oth1str}, nil, nil)

		// OtherSANs allowed, bogus OtherSANs provided, should be an error.
		addOtherSANTests(useCSRs, false, allowAll, true, []string{"foobar"}, nil, nil)
		if useCSRs {
			// OtherSANs not allowed, valid OtherSANs provided via CSR, should be an error.
			addOtherSANTests(useCSRs, true, allowNone, true, nil, []otherNameUtf8{oth1}, nil)
		}
	}

	// Lease tests
	{
		roleTestStep.ErrorOk = true
		roleVals.Lease = ""
		roleVals.MaxTTL = 0
		addTests(nil)

		roleVals.Lease = "12h"
		roleVals.MaxTTL = 6 * time.Hour
		addTests(nil)

		roleTestStep.ErrorOk = false
		roleVals.TTL = 0
		roleVals.MaxTTL = 12 * time.Hour
	}

	// Listing test
	ret = append(ret, TestStep{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Check: func(resp *logical.Response) error {
			if resp.Data == nil {
				return fmt.Errorf("nil data")
			}

			keysRaw, ok := resp.Data["keys"]
			if !ok {
				return fmt.Errorf("no keys found")
			}

			keys, ok := keysRaw.([]string)
			if !ok {
				return fmt.Errorf("could not convert keys to a string list")
			}

			if len(keys) != 1 {
				return fmt.Errorf("unexpected keys length of %d", len(keys))
			}

			if keys[0] != "test" {
				return fmt.Errorf("unexpected key value of %s", keys[0])
			}

			return nil
		},
	})

	return ret
}

func setCerts() {
	cak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	marshaledKey, err := x509.MarshalECPrivateKey(cak)
	if err != nil {
		panic(err)
	}
	keyPEMBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: marshaledKey,
	}
	ecCAKey = strings.TrimSpace(string(pem.EncodeToMemory(keyPEMBlock)))
	if err != nil {
		panic(err)
	}
	subjKeyID, err := certutil.GetSubjKeyID(cak)
	if err != nil {
		panic(err)
	}
	caCertTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "root.localhost",
		},
		SubjectKeyId:          subjKeyID,
		DNSNames:              []string{"root.localhost"},
		KeyUsage:              x509.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotAfter:              time.Now().Add(262980 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, cak.Public(), cak)
	if err != nil {
		panic(err)
	}
	caCertPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}
	ecCACert = strings.TrimSpace(string(pem.EncodeToMemory(caCertPEMBlock)))

	rak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	marshaledKey = x509.MarshalPKCS1PrivateKey(rak)
	keyPEMBlock = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: marshaledKey,
	}
	rsaCAKey = strings.TrimSpace(string(pem.EncodeToMemory(keyPEMBlock)))
	if err != nil {
		panic(err)
	}
	subjKeyID, err = certutil.GetSubjKeyID(rak)
	if err != nil {
		panic(err)
	}
	caBytes, err = x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, rak.Public(), rak)
	if err != nil {
		panic(err)
	}
	caCertPEMBlock = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}
	rsaCACert = strings.TrimSpace(string(pem.EncodeToMemory(caCertPEMBlock)))
}

// Performs some validity checking on the returned bundles
func checkCertsAndPrivateKey(keyType string, key crypto.Signer, usage x509.KeyUsage, extUsage x509.ExtKeyUsage, validity time.Duration, certBundle *certutil.CertBundle) (*certutil.ParsedCertBundle, error) {
	parsedCertBundle, err := certBundle.ToParsedCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error parsing cert bundle: %s", err)
	}

	if key != nil {
		switch keyType {
		case "rsa":
			parsedCertBundle.PrivateKeyType = certutil.RSAPrivateKey
			parsedCertBundle.PrivateKey = key
			parsedCertBundle.PrivateKeyBytes = x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))
		case "ec":
			parsedCertBundle.PrivateKeyType = certutil.ECPrivateKey
			parsedCertBundle.PrivateKey = key
			parsedCertBundle.PrivateKeyBytes, err = x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
			if err != nil {
				return nil, fmt.Errorf("error parsing EC key: %s", err)
			}
		}
	}

	switch {
	case parsedCertBundle.Certificate == nil:
		return nil, fmt.Errorf("did not find a certificate in the cert bundle")
	case len(parsedCertBundle.CAChain) == 0 || parsedCertBundle.CAChain[0].Certificate == nil:
		return nil, fmt.Errorf("did not find a CA in the cert bundle")
	case parsedCertBundle.PrivateKey == nil:
		return nil, fmt.Errorf("did not find a private key in the cert bundle")
	case parsedCertBundle.PrivateKeyType == certutil.UnknownPrivateKey:
		return nil, fmt.Errorf("could not figure out type of private key")
	}

	switch {
	case parsedCertBundle.PrivateKeyType == certutil.RSAPrivateKey && keyType != "rsa":
		fallthrough
	case parsedCertBundle.PrivateKeyType == certutil.ECPrivateKey && keyType != "ec":
		return nil, fmt.Errorf("given key type does not match type found in bundle")
	}

	cert := parsedCertBundle.Certificate

	if usage != cert.KeyUsage {
		return nil, fmt.Errorf("expected usage of %#v, got %#v; ext usage is %#v", usage, cert.KeyUsage, cert.ExtKeyUsage)
	}

	// There should only be one ext usage type, because only one is requested
	// in the tests
	if len(cert.ExtKeyUsage) != 1 {
		return nil, fmt.Errorf("got wrong size key usage in generated cert; expected 1, values are %#v", cert.ExtKeyUsage)
	}
	switch extUsage {
	case x509.ExtKeyUsageEmailProtection:
		if cert.ExtKeyUsage[0] != x509.ExtKeyUsageEmailProtection {
			return nil, fmt.Errorf("bad extended key usage")
		}
	case x509.ExtKeyUsageServerAuth:
		if cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
			return nil, fmt.Errorf("bad extended key usage")
		}
	case x509.ExtKeyUsageClientAuth:
		if cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
			return nil, fmt.Errorf("bad extended key usage")
		}
	case x509.ExtKeyUsageCodeSigning:
		if cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
			return nil, fmt.Errorf("bad extended key usage")
		}
	}

	if math.Abs(float64(time.Now().Add(validity).Unix()-cert.NotAfter.Unix())) > 20 {
		return nil, fmt.Errorf("certificate validity end: %s; expected within 20 seconds of %s", cert.NotAfter.Format(time.RFC3339), time.Now().Add(validity).Format(time.RFC3339))
	}

	return parsedCertBundle, nil
}

var (
	initTest  sync.Once
	rsaCAKey  string
	rsaCACert string
	ecCAKey   string
	ecCACert  string
)
