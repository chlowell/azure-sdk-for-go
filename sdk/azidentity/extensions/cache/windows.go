//go:build go1.18 && windows
// +build go1.18,windows

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
package cache

import (
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity/internal"
	"github.com/AzureAD/microsoft-authentication-extensions-for-go/extensions/accessor"
)

func storage(o internal.TokenCachePersistenceOptions) (accessor.Accessor, error) {
	name := "msal.cache"
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	f := filepath.Join(home, ".IdentityService", name)
	a, err := accessor.New(f)
	return a, err
}
