//go:build go1.18 && linux
// +build go1.18,linux

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity/internal"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/log"
	"github.com/AzureAD/microsoft-authentication-extensions-for-go/extensions/accessor"
	"github.com/AzureAD/microsoft-authentication-extensions-for-go/extensions/accessor/file"
)

func storage(o internal.TokenCachePersistenceOptions) (accessor.Accessor, error) {
	name := "msal.cache"
	var a accessor.Accessor
	var err error
	a, err = accessor.New(name)
	if err == nil {
		// try reading to determine whether libsecret is usable
		if _, err = a.Read(context.TODO()); err != nil {
			msg := fmt.Sprintf(`cache encryption is impossible because libsecret isn't installed or is unusable: %q. Set "AllowUnencryptedStorage" to store the cache unencrypted instead of returning this error`, err)
			err = errors.New(msg)
		}
	}
	if err != nil && o.AllowUnencryptedStorage {
		log.Write(azidentity.EventAuthentication, "falling back to unencrypted storage because encryption isn't possible")
		home := ""
		if home, err = os.UserHomeDir(); err == nil {
			f := filepath.Join(home, ".IdentityService", name)
			a, err = file.New(f)
		}
	}
	return a, err
}
