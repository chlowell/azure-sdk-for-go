//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
package internal

import "github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"

// TokenCachePersistenceOptions contains options for persistent token caching
type TokenCachePersistenceOptions struct {
	// AllowUnencryptedStorage controls whether the cache should fall back to storing its data in plain text
	// when encryption isn't possible. Setting this to true doesn't disable encryption. The cache always tries
	// to encrypt its data.
	AllowUnencryptedStorage bool
	// Name is the name of the cache, used to isolate its data from other applications. Defaults to the name
	// of the cache shared by the Azure SDK and some Microsoft dev tools.
	Name string
}

var NewCache = func(TokenCachePersistenceOptions) (cache.ExportReplace, error) {
	return nil, nil
}
