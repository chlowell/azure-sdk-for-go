//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
package cache

import (
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity/internal"
	extcache "github.com/AzureAD/microsoft-authentication-extensions-for-go/extensions/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
)

func init() {
	internal.NewCache = func(o internal.TokenCachePersistenceOptions) (cache.ExportReplace, error) {
		a, err := storage(o)
		if err != nil {
			return nil, err
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		name := "msal.cache"
		if o.Name != "" {
			name = o.Name
		}
		lockfile := filepath.Join(home, ".IdentityService", name+".lockfile")
		c, err := extcache.New(a, lockfile)
		return c, err
	}
}
