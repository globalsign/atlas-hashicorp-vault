package atlas

import (
	"fmt"
	"testing"
)

func Test_ValidateIssueCertRequest(t *testing.T) {

	var vp = ValidationPolicy{
		ExtendedKeyUsages: EKUPolicy{
			EKUs: ListPolicy{
				Static:   true,
				List:     []string{"1.3.6.1.5.5.7.3.1"},
				MinCount: 1,
				MaxCount: 1,
			},
			Critical: false,
		},
		KeyUsages: KeyUsagePolicy{
			ContentCommitment:  "STATIC_TRUE",
			CrlSign:            "STATIC_TRUE",
			DataEncipherment:   "STATIC_FALSE",
			DecipherOnly:       "OPTIONAL",
			DigitalSignature:   "STATIC_TRUE",
			EncipherOnly:       "STATIC_TRUE",
			KeyAgreement:       "STATIC_TRUE",
			KeyCertificateSign: "STATIC_TRUE",
			KeyEncipherment:    "STATIC_TRUE",
		},
		Signature: SignaturePolicy{
			Algorithm: SimpleListPolicy{
				List:     []string{},
				Presence: "STATIC",
			},
			HashAlgorithm: SimpleListPolicy{
				List:     []string{},
				Presence: "OPTIONAL",
			},
		},
	}

	var req = IssueCertRequest{
		Validity:  &Validity{},
		SubjectDN: &SubjectDN{},
		SAN:       &SAN{},
		SubjectDA: &SubjectDA{},
		KeyUsages: &KeyUsages{
			DigitalSignature:   newBool(true),
			ContentCommitment:  newBool(true),
			KeyEncipherment:    newBool(true),
			DataEncipherment:   newBool(true),
			KeyAgreement:       newBool(true),
			KeyCertificateSign: newBool(true),
			CrlSign:            newBool(true),
			EncipherOnly:       newBool(true),
			DecipherOnly:       newBool(true),
		},
		ExtendedKeyUsages:   []string{"1.2.3.4.5"},
		QualifiedStatements: &QualifiedStatements{},
		MsExtensionTemplate: &MsExtensionTemplate{},
		CustomExtensions:    map[string]string{},
		Signature: &Signature{
			Algorithm:     "RSA",
			HashAlgorithm: "SHA-256",
		},
		PublicKey:          "",
		PublicKeySignature: "",
	}

	req.ValidateIssueCertRequest(vp)
	// Check ExtendedKeyUsages
	if len(req.ExtendedKeyUsages) > 0 {
		panic(fmt.Errorf("Wrong ExtendedKeyUsages Submitted: %v", req.ExtendedKeyUsages))
	}

	// Check KeyUsages
	if req.KeyUsages.ContentCommitment != nil {
		panic(fmt.Errorf("Wrong ContentCommitment Submitted: %v", *req.KeyUsages.ContentCommitment))
	}

	if req.KeyUsages.DecipherOnly == nil {
		panic(fmt.Errorf("Wrong DecipherOnly Submitted: %v", *req.KeyUsages.DecipherOnly))
	}

	if req.KeyUsages.DataEncipherment != nil {
		panic(fmt.Errorf("Wrong DataEncipherment Submitted: %v", *req.KeyUsages.DataEncipherment))
	}

	// Check Signature
	if req.Signature.Algorithm != "" {
		panic(fmt.Errorf("Wrong Algorithm Submitted: %v", req.Signature.Algorithm))
	}
	if req.Signature.HashAlgorithm != "SHA-256" {
		panic(fmt.Errorf("Wrong HashAlgorithm Submitted: %v", req.Signature.HashAlgorithm ))
	}
}
