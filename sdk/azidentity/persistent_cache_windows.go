//go:build go1.18 && windows
// +build go1.18,windows

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/AzureAD/microsoft-authentication-extensions-for-go"
)

func init() {
	getAccessor = func(o *TokenCachePersistenceOptions) (msalext.CacheAccessor, error) {
		name := "msal.cache"
		if o.Name != "" {
			name = o.Name
		}
		if ad, ok := os.LookupEnv("LOCALAPPDATA"); ok {
			f := filepath.Join(ad, ".IdentityService", name)
			return msalext.NewWindowsAccessor(f)
		} else {
			return nil, errors.New("no value for LOCALAPPDATA")
		}
	}
}
