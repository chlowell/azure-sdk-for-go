//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"fmt"
	"runtime"

	"github.com/AzureAD/microsoft-authentication-extensions-for-go"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
)

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

// getAccessor returns a cache accessor appropriate for the platform. When it's nil, no accessor is available.
var getAccessor func(*TokenCachePersistenceOptions) (msalext.CacheAccessor, error)

// loadPersistentCache loads a persistent cache for the given options, if possible. Returns nil when o is nil.
func loadPersistentCache(o *TokenCachePersistenceOptions) (cache.ExportReplace, error) {
	var c cache.ExportReplace
	var err error
	if o != nil {
		if getAccessor == nil {
			return nil, fmt.Errorf("persistent caching isn't supported for %s", runtime.GOOS)
		}
		var a msalext.CacheAccessor
		a, err = getAccessor(o)
		if err == nil {
			c, err = msalext.NewTokenCache(a, "/home/chlowe/test.lock")
		}
	}
	return c, err
}
