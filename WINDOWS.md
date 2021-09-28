

# Windows Setup

The below instructutions assume a Windows 10 Enviorment, with a x86 archtecture, and PowerShell 3.0 or newer.

We assume you dont have an exising vault server running, and you have an Atlas account with an appropriate profile.

To ensure you dont have an existing vault server please run the following powershell command to stop the active vault.

```powershell
Stop-Process -Name Vault
```

### 1. Open PowerShell

### 2. Install the Hashicorp vault Binary

Please follow Hashicorps instructions for installing the vault:
https://www.vaultproject.io/docs/install#precompiled-binaries

### 3. Create a directory for our plugin
```powershell
New-Item -ItemType "directory" -Name win_plugin
```
#### 4. Download our plugin into this new directory
```powershell
Invoke-RestMethod -Uri https://github.com/globalsign/atlas-hashicorp-vault/releases/latest/download/atlas-windows-amd64 -Method Get -OutFile win_plugin/atlas.exe
```

> Note: that the URL will change once repository is made public.

### 5. Run vault with the plugin directory specified.
```powershell
vault server -dev -dev-root-token-id=root -dev-plugin-dir=win_plugin
```
For simplicity we are running in dev mode.
### 6. Open a new Additional Powershell Terminal

All further instructions will be ran in the new powershell terminal

### 7. Export routing enviorment vars by running
```powershell
$env:VAULT_ADDR="http://127.0.0.1:8200"
```
### 8. Verify the connection.

```powershell
vault status
```

You should see:
```
PS C:\Users\Andre> vault status
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         1.6.0
Storage Type    inmem
Cluster Name    vault-cluster-6dae5f2b
Cluster ID      8f864a9c-31ad-88ef-f156-ff11264009cd
HA Enabled      false
```

### 9. Register the plugin
```powershell
vault secrets enable --path=atlas atlas.exe
```

### 10. Read keys
Use the below commands to read and convert your mTLS files. Please replace the paths with the literal path to your cert and keys.

```powershell
 $mtls_cert = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\Andre\vtest\my_cert.pem"))
```

```powershell
 $mtls_key = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\Andre\vtest\my_key.pem"))
```

> Note: Key file should be in PEM format and must be decrypted.

### 11. Authenticate the Plugin with Atlas

Please run the below but replace vaulues in `<>` with your own.

```powershell
vault write atlas/config/authn api_key="<Your_Atlas_API_Key>" api_secret="<Your_Atlas_API_Secret>" api_cert="$mtls_cert" api_cert_key="$mtls_key"
```

### 12. Configure a Vault role that maps to a set of permissions.
```powershell
vault write atlas/roles/my-role allow_any_name=true enforce_hostnames=false
```

This creates a role named "my-role". When users generate certificates against
this role, Vault will validate the certificate request against the permissions.
Vault will then send the certificate request to be issued by your Atlas instance.

The above role constraints are permissive, we would recommend tighter rules to fit your use case. Note that you atlas account
policy will also apply to issued certificates, only certificates that meet both local and atlas policies will be issued,.


### 13.  Issue a Certificate through vault using your role
```powershell
vault write atlas/issue/my-role common_name="example.com" ttl=24h
```

This creates a Private Key and a Certificate using the provided role and certificate configuration. You can reference this
certificate in future requests using the serial number returned in the response.

Keep note of your private key, you won't be able to retrieve it in future requests.

> Note: The above assumes your atlas account has permissions to issues certificates for example.com

### 14. List Your certificates
```powershell
vault list atlas/certs
```

This returns a list of certificate serial numbers that have been issued through this vault cluster. This can be used for
getting more details or revoking certificates.

### 15. Get Details on a Certificate
> Note: Please replace 00-00-00-00-... with your certificate serial number

```powershell
vault read atlas/cert/00-00-00-00-00-00-00-...
```

This will give you the certificate pem and other issuance metadata, you can get the serial number from the certificate itself if
you would like to reverse this, but you must separate hex pairs with `-`.

Note that you can only get details on certificates issued through this vault cluster, once a certificate is expired
or revoked it will remain visible here for a short period of time.


### 16. Revoking a Certificate
> Note: Please replace 00-00-00-00-... with your certificate serial number

```powershell
vault write atlas/revoke serial_number=00-00-00-00-00-00-00-...
```

Just like Get details this requires a `-` separated serial number. This will have your atlas account add the certificate to
relevant revocation lists, and update its status within the vault cluster.

If your revoking lots of certificates it's a good idea to invoke tidy, which will clean up excess metadata within vault.

```powershell
vault write -force atlas/tidy
```
