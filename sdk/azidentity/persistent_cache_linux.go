//go:build go1.18 && linux
// +build go1.18,linux

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/internal/log"
	"github.com/AzureAD/microsoft-authentication-extensions-for-go"
)

func init() {
	getAccessor = func(o *TokenCachePersistenceOptions) (msalext.CacheAccessor, error) {
		var a msalext.CacheAccessor
		name := "msal.cache"
		if o.Name != "" {
			name = o.Name
		}
		// a, err := msalext.NewLibsecretAccessor(name)
		a = msalext.NewKeyRingAccessor("cachefilepath", "collection", "schema", "label", "key1", "value1", "key2", "value2")
		var err error
		if err == nil {
			// the constructor found the required dependencies, however that doesn't guarantee
			// the accessor can use the keyring; for example this will fail in most SSH sessions
			// because the keyring can't be unlocked
			_, err = a.Read(context.Background())
		}
		if err != nil {
			message := fmt.Sprintf("cache encryption isn't possible in this environment: %q", err)
			if o.AllowUnencryptedStorage {
				home := ""
				if home, err = os.UserHomeDir(); err == nil {
					f := filepath.Join(home, ".IdentityService", name)
					a = msalext.NewFileAccessor(f)
					log.Writef(EventAuthentication, message+". Falling back to unencrypted storage")
				}
			} else {
				return nil, errors.New(message + ". Set AllowUnencryptedStorage to store the cache without encryption instead of returning this error")
			}
		}
		return a, err
	}
}
