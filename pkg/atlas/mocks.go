package atlas

import "context"

type MockClient struct {
	OutError    error
	OutCert     *Certificate
	OutCertList []string
	OutPolicy   ValidationPolicy
}

var (
	MockCert = &Certificate{
		Status: "ISSUED",
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIEcjCCA1qgAwIBAgIQAb4ElB1WWfbjZRykITZ+GDANBgkqhkiG9w0BAQsFADBS
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
AxMfR2xvYmFsU2lnbiBOb24tUHVibGljIEhWQ0EgRGVtbzAeFw0yMDExMjQwODM3
NTFaFw0yMDEyMjYwODM4MjFaMEExCzAJBgNVBAYTAlVTMRswGQYDVQQKDBJHbG9i
YWxTaWduIEFFRyBEZXYxFTATBgNVBAMMDGV4YW1wbGVfcm9sZTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMWU8jxBwPQquEM1VcFh1OUakvpD2q5WsJs3
9AAgI2ctksZvzw32AZNBto63noiOWQTYts+9SPNgbneaUviHwjdaJ2AOAO6yl5z7
45y12254okCLU96m8JAHFsrN5yFyV45GKpmWAWmD8iUJRgTOSWY9u2SdNWJkxmTI
PVrNPLqTPK+LuO5x+HGhQIy78Tgxoz8JXN1YO9sRoPOAjLCeTFkN0iCF+8lCfSDV
biE7iK0OSYEcmeSWV5Q/yUIxc4KPGB4snUHZLUPwJwx8+58yCdb9Q6O6Bn6zqp3l
6jRdPYD7VFHdebVLBnx9hDOtZ2RKOBTOzLLQXPcU/8gBJA7Yfg0CAwEAAaOCAVMw
ggFPMA4GA1UdDwEB/wQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4E
FgQUhVL3S4+eVDv9rtOMlqpQM8YSHigwCQYDVR0TBAIwADCBlgYIKwYBBQUHAQEE
gYkwgYYwPAYIKwYBBQUHMAGGMGh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2Nh
L2dzbnBodmNhZGVtb3NoYTJnMzBGBggrBgEFBQcwAoY6aHR0cDovL3NlY3VyZS5n
bG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NucGh2Y2FkZW1vc2hhMmczLmNydDAfBgNV
HSMEGDAWgBRnSwfpCfHxezLMvYUcTicNzqHMbDBEBgNVHR8EPTA7MDmgN6A1hjNo
dHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2NhL2dzbnBodmNhZGVtb3NoYTJnMy5j
cmwwDQYJKoZIhvcNAQELBQADggEBAJC92kS4QJyubFMi54GwmY0OVOj5VSzp8hb0
idct117ms63oNCU/WYDI1rC/wUvrI8PIE/dLsD3MYGKCbl2w2ZAzY6FQI646PC3J
JC7TEIPnbpcf8epfC3aglOj26IERgagVoWo137kzEsKN7bNy2zrNiTu4bZOm1zFq
LP0k4EQ6r1uCLVLj7BOkSQ8WZ552usv26eTYqppl7yL0A+nrq8CL3KFVwbfsMz2C
xV3jSxHKuZ8+oEpD+R8rPlH2WSgqPxu0TIowGXGoKwcF6/5qJBj6R5ZKC/y5E9Qm
SIWufet+dT+AvaVtKLDu1DewwXiK177L2iv6U7cc1mOV4xL91Qc=
-----END CERTIFICATE-----`,
		UpdatedAt: 1606207103,
	}

	MockCACert = `
-----BEGIN CERTIFICATE-----
MIIDbjCCAlagAwIBAgIOSETcwm+2g5xjwYbw8ikwDQYJKoZIhvcNAQELBQAwUjEL
MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKDAmBgNVBAMT
H0dsb2JhbFNpZ24gTm9uLVB1YmxpYyBIVkNBIERlbW8wHhcNMTYwNzIwMDAwMDAw
WhcNMjYwNzIwMDAwMDAwWjBSMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
U2lnbiBudi1zYTEoMCYGA1UEAxMfR2xvYmFsU2lnbiBOb24tUHVibGljIEhWQ0Eg
RGVtbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALZr0Una3n3CTWMf
+TGoc3sFXqWIpAasR2ULxVuziCQVs7Z2/ha6iNhQ2JITZzTu5ZZHwrgvxTwdLSq7
Y9H22u1sahJYMElQOsoEMERwGKGU92HpqxrinYi54mZ0xU1vYVyMAPfOvOh9NUgo
KXCuza27wIfl00A7HO8nq0hoYxmezrVIUyObLuQir43mwruov31nOhFeYqxNWPkQ
VDGOBqRGp6KkEMlKsV9/Tyw0JyRko1cDukS6Oacv1NSU4rz6+aYqvCQSZEy5IbUd
KS46aQ1FO9c4jVhJ3uTzJ/nJ5W4B9RP//JpLt2ey9XvfvuJW8s9qjJtY18frgCoD
yilhHk0CAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w
HQYDVR0OBBYEFGdLB+kJ8fF7Msy9hRxOJw3OocxsMA0GCSqGSIb3DQEBCwUAA4IB
AQBQIVeyhjtZ+T30LY8AlVe0jya9yBuCSqXld9Lesm1RiE2MIjW1cDueKlxa6DFT
7Ysm+s0Q171r5JB/ZgLG2TyjCBEocxSLdYrBy+V3Gb9sN2KToyeE01nTrK85E+Tp
JXVAlgfuYsntV5GQ/cut+Wpl6QuJHfXWRcXQo0/nNG15A79Z84LTcM0f5qVkvDTC
OXiCVR4HYFF5G39qaKaBCVuWnBCOdNKF7ESQVxc1UDibTFLFxHHKd8hrHe7mdSip
jkU8e4uzGpVAnJGLYncRQtowXHPc14prEcYvzxvXphgF1RYdp9Tu0wAha+Tjt0VL
eFSle46vwuyv8BzkS+rQJ8Kb
-----END CERTIFICATE-----
	`

	MockCertSerial = "01be04941d5659f6e3651ca421367e18"
)

func (c *MockClient) Login(ctx context.Context) error {
	return c.OutError
}

// GetConfig gets the configuration profile for your Atlas Instance, Refer to the API documentation for more info.
func (c *MockClient) GetConfig(ctx context.Context) (ValidationPolicy, error) {
	if c.OutError != nil {
		return ValidationPolicy{}, c.OutError
	}
	return c.OutPolicy, nil
}

// GetTrustChain returns the Certificate Authority chain used by the instance, output is an array of PEM encoded certs.
func (c *MockClient) GetTrustChain(ctx context.Context) ([]string, error) {
	if c.OutError != nil {
		return nil, c.OutError
	}
	if c.OutCertList == nil {
		c.OutCertList = []string{MockCACert}
	}
	return c.OutCertList, nil
}

// IssueCertificate will that the provided CSR and Parameters to request issuance of a certificate from your Atlas Instance.
//
// Note that this issuance call actually performs a Issue then GET for convince.
func (c *MockClient) IssueCertificate(ctx context.Context, req *IssueCertRequest) (*Certificate, error) {
	if c.OutError != nil {
		return nil, c.OutError
	}
	if c.OutCert == nil {
		c.OutCert = MockCert
	}
	return c.OutCert, nil
}

// GetCert gets the certificate for the provided serial number.
func (c *MockClient) GetCert(ctx context.Context, id string) (*Certificate, error) {
	if c.OutError != nil {
		return nil, c.OutError
	}
	if c.OutCert == nil {
		c.OutCert = MockCert
	}
	return c.OutCert, nil
}

// RevokeCert revokes the certificate with the provided serial number.
func (c *MockClient) RevokeCert(ctx context.Context, id string) error {
	return c.OutError
}
