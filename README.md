# GlobalSign Atlas Certificate Provider for Hashicorp Vault 

`atlas-hashicorp-vault` plugin lets you manage issue GlobalSign Atlas backed certificates in vault.

- [API Docs](https://github.com/globalsign/atlas-hashicorp-vault/blob/master/website/pages/api-docs/secret/vault-plugin-secrets-atlas/index.mdx)
- [Getting Started Guide](https://github.com/globalsign/atlas-hashicorp-vault/blob/master/website/pages/docs/secrets/vault-plugin-secrets-atlas/index.mdx)
- [MicroK8s Certificate Manager Tutorial](https://github.com/globalsign/atlas-hashicorp-vault/blob/master/K8S_CERT_MANAGER.md)
- [Releases](https://github.com/globalsign/atlas-hashicorp-vault/releases)

## Demo
[![asciicast](https://asciinema.org/a/K5k9khe33IN7Ewot6yMN6yjBB.svg)](https://asciinema.org/a/K5k9khe33IN7Ewot6yMN6yjBB) 
## Installation

Before you can use the Plugin's API you will need to install the vault plugin:

_**(Note: We have automated most of these steps and user can directly navigate to** `atlas-hashicorp-vault` **and run** `make`)_
1. Create the [directory](https://www.vaultproject.io/docs/internals/plugins#plugin-directory)
   where your Vault server will look for plugins

2. Download the latest `atlas-hashicorp-vault` plugin [release package](../../releases/latest)
   for your operating system. Note that the URL for the source binary file, referenced below, changes as new versions of the
   plugin are released.

   ```bash
   $ curl https://github.com/globalsign/atlas-hashicorp-vault/releases/download/v1.0/atlas-linux-amd64 -o /etc/vault/vault_plugins/atlas
   $ chmod +x /etc/vault/vault_plugins/atlas
   ```

3. Update the Vault [server configuration](https://www.vaultproject.io/docs/configuration/)
   to specify the plugin directory:

   ```hcl
   plugin_directory = "/etc/vault/vault_plugins"
   ```

4. Start your Vault using the [server command](https://www.vaultproject.io/docs/commands/server).

5. Get the SHA-256 checksum of the `atlas-hashicorp-vault` plugin binary:

   ```bash
   $ PLUGIN_SHA256=$(sha256sum /etc/vault/vault_plugins/atlas-hashicorp-vault | cut -d' ' -f1)
   ```

6. Register the `atlas-hashicorp-vault` plugin in the Vault
   [system catalog](https://www.vaultproject.io/docs/internals/plugins#plugin-catalog):

   ```bash
   $ vault write sys/plugins/catalog/secret/atlas \
       sha_256="$PLUGIN_SHA256" command="atlas"
   Success! Data written to: sys/plugins/catalog/secret/atlas
   ```

To Configure the installed plugin refer to our [Getting Started Guide](https://github.com/globalsign/atlas-hashicorp-vault/blob/master/website/pages/docs/secrets/vault-plugin-secrets-atlas/index.mdx)

## Cert-Manager Integration

The Atlas secret engine plugin works with Kubernetes [cert-manager](https://cert-manager.io/docs/). If you would like to try this locally, you can run `./scripts/test-cert-manager.sh` on an linux computer.

You can see it working here:

[![asciicast](https://asciinema.org/a/BvSo8Hw1vTjBVaOmLeUp78XEb.svg)](https://asciinema.org/a/BvSo8Hw1vTjBVaOmLeUp78XEb)

You can refer to our [MicroK8s certificate manager](https://github.com/globalsign/atlas-hashicorp-vault/blob/master/K8S_CERT_MANAGER.md) tutorial if you would like to hookup GlobalSign Atlas to Kubernetes Certificate manager.

## Development

You can develop this plugin using the golang tool-chain and the provided Makefile.

By running `make` your system will compile the current source, and start a vault server in dev mode.

For convince, we recommend running `scripts/test-cli.sh` to actuate the plugins functionality. If you are doing this often we recommend setting development credentials as described below, it will reduce your iteration times.

If you are working with the Atlas Client library you will need to have development credentials configured, as it performs integration tests with the Atlas backend.
### Development Credentials

Integration test require GlobalSign Atlas credentials, by default these tests will prompt you for your credentials, it will additionally give you the option to persist them. You can manually engage this process by running the `./scripts/login.sh` in bash.

The development helpers will ask for plaintext API credentials and PEM formatted client mTLS credentials.
## Contributing

We expect changes to meet Hashicorp Vaults' style, to have tests, and to keep coverage above 70%.
