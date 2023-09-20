//go:build go1.18 && windows
// +build go1.18,windows

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package broker

import (
	// "github.com/AzureAD/microsoft-authentication-library-for-go/broker"
)

type BrokerOptions struct {
	// EnableMSAPassthrough allows the credential to authenticate with Microsoft Account (MSA) passthrough during
	// brokered authentication.
	// TODO: could this be an environment variable?
	EnableMSAPassthrough bool

	// MSALRuntimePath is the path to the MSAL runtime DLL.
	// TODO: this isn't optional
	MSALRuntimePath string
}

func Initialize(msalruntimePath string) error {
	return nil
}
