// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/mock"
	"github.com/stretchr/testify/require"
)

func TestAzurePipelinesServiceConnectionCredential(t *testing.T) {
	srv, close := mock.NewServer(mock.WithTransformAllRequestsToTestServerUrl())
	defer close()
	connectionID := "connection"
	vs := map[string]string{
		systemAccessToken:                 "token",
		systemJobID:                       "job",
		systemPlanID:                      "plan",
		systemTeamFoundationCollectionURI: srv.URL(),
		systemTeamProjectID:               "project",
	}
	for k, v := range vs {
		t.Setenv(k, v)
	}
	expected, err := url.Parse(fmt.Sprintf(
		"%s/%s/_apis/distributedtask/hubs/build/plans/%s/jobs/%s/oidctoken?api-version=%s&serviceConnectionId=%s",
		vs[systemTeamFoundationCollectionURI], vs[systemTeamProjectID], vs[systemPlanID], vs[systemJobID], oidcAPIVersion, connectionID,
	))
	require.NoError(t, err, "test bug: expected URL should parse")
	srv.AppendResponse(mock.WithBody(tenantMetadata(fakeTenantID)))
	srv.AppendResponse(
		mock.WithBody([]byte(fmt.Sprintf(`{"oidcToken":%q}`, vs[systemAccessToken]))),
		mock.WithPredicate(func(r *http.Request) bool {
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, expected.Host, r.Host)
			require.Equal(t, expected.Path, r.URL.Path)
			require.Equal(t, expected.RawQuery, r.URL.RawQuery)
			return true
		}),
	)
	srv.AppendResponse()
	srv.AppendResponse(mock.WithBody([]byte(fmt.Sprintf(`{"access_token":%q,"expires_in": 3600}`, tokenValue))))
	o := AzurePipelinesServiceConnectionCredentialOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: srv,
		},
		// without this the test would have to fake the instance discovery endpoint
		DisableInstanceDiscovery: true,
	}
	cred, err := NewAzurePipelinesServiceConnectionCredential(fakeTenantID, fakeClientID, connectionID, &o)
	require.NoError(t, err)
	tk, err := cred.GetToken(ctx, testTRO)
	require.NoError(t, err)
	require.Equal(t, tokenValue, tk.Token)
}
