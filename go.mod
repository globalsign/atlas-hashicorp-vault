module github.com/globalsign/atlas-hashicorp-vault

go 1.12

require (
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef
	github.com/davecgh/go-spew v1.1.1
	github.com/fatih/structs v1.1.0
	github.com/go-test/deep v1.0.7
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/vault v1.6.0
	github.com/hashicorp/vault/api v1.0.5-0.20201001211907-38d91b749c77
	github.com/hashicorp/vault/sdk v0.1.14-0.20201109203410-5e6e24692b32
	github.com/mitchellh/mapstructure v1.3.3
	github.com/ryanuber/go-glob v1.0.0
	github.com/stretchr/testify v1.6.1
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/net v0.0.0-20200625001655-4c5254603344
)

replace github.com/globalsign/atlas-hashicorp-vault v0.0.0 => ./
