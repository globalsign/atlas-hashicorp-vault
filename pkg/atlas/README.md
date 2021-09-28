# GlobalSign ATLAS Client

Documentation: https://www.globalsign.com/en/resources/apis/api-documentation/globalsign_atlas_api_documentation_version_v2.html


## Client Flow

1. Configure Client
2. Get Access Token
3. Get Issuance Policy

## Cert Issuance Flow

1. Get Initial Request
2. Check against policy
3. Populate static fields
4. Generate RSA Keypair
5. Sign Payload
6. Embeded Data


## Error Behavior

2XX -> Continue
401 -> Reauthorize with New Token
4XX -> Abort and Error
503 -> Backoff Retry


# Formatting

Outbound: `application/json;charset=utf-8`
Inbound: `application/json;charset=utf-8`
Inbound Error: `application/problem+json;charset=utf-8`

# Cert Issuance

```
{
    validity: {
        not_before: now.epoch(),
    },
    subject_dn: {
        "common_name": "John Doe",
        "country": "US",
        "organization": "GlobalSign AEG Dev",
        "organizational_unit": [
            "Development"
        ],
        "email": "mailto:test_cert@aegdomain.com"
    },
    sam: {
        "emails": "test_cert@aegdomain.com"
    },
    "key_usages": {
        "content_commitment": false,
        "crl_sign": false,
        "data_encipherment": false,
        "decipher_only": false,
        "digital_signature": true,
        "encipher_only": false,
        "key_agreement": true,
        "key_certificate_sign": false,
        "key_encipherment": true
    },

}
```