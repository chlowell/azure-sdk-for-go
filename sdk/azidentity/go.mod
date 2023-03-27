module github.com/Azure/azure-sdk-for-go/sdk/azidentity

go 1.18

replace github.com/AzureAD/microsoft-authentication-extensions-for-go => /home/chlowe/scratch/microsoft-authentication-extensions-for-go

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.5.0-beta.1
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.1.2
	github.com/AzureAD/microsoft-authentication-extensions-for-go v0.1.0
	github.com/AzureAD/microsoft-authentication-library-for-go v0.9.0
	github.com/golang-jwt/jwt/v4 v4.4.3
	github.com/google/uuid v1.3.0
	golang.org/x/crypto v0.1.0
)

require (
	github.com/billgraziano/dpapi v0.4.0 // indirect
	github.com/dnaeon/go-vcr v1.1.0 // indirect
	github.com/keybase/go-keychain v0.0.0-20230307172405-3e4884637dd1 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
