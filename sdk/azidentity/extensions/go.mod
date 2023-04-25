module github.com/Azure/azure-sdk-for-go/sdk/azidentity/extensions

go 1.20

replace (
	github.com/Azure/azure-sdk-for-go/sdk/azidentity => ../
	github.com/AzureAD/microsoft-authentication-extensions-for-go => ../../../../scratch/microsoft-authentication-extensions-for-go
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.3.0
	github.com/AzureAD/microsoft-authentication-extensions-for-go v0.0.0-00010101000000-000000000000
	github.com/AzureAD/microsoft-authentication-library-for-go v1.0.0
)
