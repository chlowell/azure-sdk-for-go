// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
)

const (
	credNameAzurePipelines = "AzurePipelinesServiceConnectionCredential"
	oidcAPIVersion         = "7.1-preview.1"

	// environment variables set by Azure Pipelines
	systemAccessToken                 = "SYSTEM_ACCESSTOKEN"
	systemJobID                       = "SYSTEM_JOBID"
	systemPlanID                      = "SYSTEM_PLANID"
	systemTeamFoundationCollectionURI = "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"
	systemTeamProjectID               = "SYSTEM_TEAMPROJECTID"
)

// AzurePipelinesCredential TODO
type AzurePipelinesCredential struct {
	collectionURI, connectionID, jobID, planID, projectID, systemToken string
	cred                                                               *ClientAssertionCredential
}

// AzurePipelinesServiceConnectionCredentialOptions contains optional parameters for AzurePipelinesServiceConnectionCredential.
type AzurePipelinesServiceConnectionCredentialOptions struct {
	azcore.ClientOptions

	// AdditionallyAllowedTenants specifies additional tenants for which the credential may acquire tokens.
	// Add the wildcard value "*" to allow the credential to acquire tokens for any tenant in which the
	// application is registered.
	AdditionallyAllowedTenants []string

	// DisableInstanceDiscovery should be set true only by applications authenticating in disconnected clouds, or
	// private clouds such as Azure Stack. It determines whether the credential requests Microsoft Entra instance metadata
	// from https://login.microsoft.com before authenticating. Setting this to true will skip this request, making
	// the application responsible for ensuring the configured authority is valid and trustworthy.
	DisableInstanceDiscovery bool
}

// NewAzurePipelinesServiceConnectionCredential TODO
func NewAzurePipelinesServiceConnectionCredential(tenantID, clientID, serviceConnectionID string, options *AzurePipelinesServiceConnectionCredentialOptions) (*AzurePipelinesCredential, error) {
	if options == nil {
		options = &AzurePipelinesServiceConnectionCredentialOptions{}
	}
	a := AzurePipelinesCredential{connectionID: serviceConnectionID}
	missing := []string{}
	ok := false
	if a.systemToken, ok = os.LookupEnv(systemAccessToken); !ok {
		missing = append(missing, systemAccessToken)
	}
	if a.jobID, ok = os.LookupEnv(systemJobID); !ok {
		missing = append(missing, systemJobID)
	}
	if a.planID, ok = os.LookupEnv(systemPlanID); !ok {
		missing = append(missing, systemPlanID)
	}
	if a.collectionURI, ok = os.LookupEnv(systemTeamFoundationCollectionURI); !ok {
		missing = append(missing, systemTeamFoundationCollectionURI)
	}
	if a.projectID, ok = os.LookupEnv(systemTeamProjectID); !ok {
		missing = append(missing, systemTeamProjectID)
	}
	if len(missing) > 0 {
		return nil, errors.New("missing values for environment variables " + strings.Join(missing, ", "))
	}
	caco := ClientAssertionCredentialOptions{
		AdditionallyAllowedTenants: options.AdditionallyAllowedTenants,
		ClientOptions:              options.ClientOptions,
		DisableInstanceDiscovery:   options.DisableInstanceDiscovery,
	}
	cred, err := NewClientAssertionCredential(tenantID, clientID, a.getAssertion, &caco)
	if err != nil {
		return nil, err
	}
	cred.client.name = credNameAzurePipelines
	a.cred = cred
	return &a, nil
}

// GetToken requests an access token from Microsoft Entra ID. Azure SDK clients call this method automatically.
func (a *AzurePipelinesCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	var err error
	ctx, endSpan := runtime.StartSpan(ctx, credNameAzurePipelines+"."+traceOpGetToken, a.cred.client.azClient.Tracer(), nil)
	defer func() { endSpan(err) }()
	tk, err := a.cred.GetToken(ctx, opts)
	return tk, err
}

func (a *AzurePipelinesCredential) getAssertion(ctx context.Context) (string, error) {
	// TODO: upgrade to 7.1
	// "${env:SYSTEM_OIDCREQUESTURI}?api-version=7.1&serviceConnectionId=${env:AZURESUBSCRIPTION_SERVICE_CONNECTION_ID}"
	url := fmt.Sprintf(
		"%s/%s/_apis/distributedtask/hubs/build/plans/%s/jobs/%s/oidctoken?api-version=%s&serviceConnectionId=%s",
		a.collectionURI, a.projectID, a.planID, a.jobID, oidcAPIVersion, a.connectionID,
	)
	url, err := runtime.EncodeQueryParams(url)
	if err != nil {
		return "", err
	}
	// req, err := runtime.NewRequest(ctx, http.MethodGet, url)
	// if err != nil {
	// 	return "", err
	// }
	// req.Raw().Header.Set("Authorization", "Bearer "+a.systemToken)
	// res, err := a.cred.client.azClient.Pipeline().Do(req)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+a.systemToken)
	res, err := doForClient(a.cred.client.azClient, req)
	if err != nil {
		return "", err
	}
	b, err := runtime.Payload(res)
	if err != nil {
		return "", err
	}
	var r struct {
		OIDCToken string `json:"oidcToken"`
	}
	err = json.Unmarshal(b, &r)
	if err != nil {
		return "", err
	}
	return r.OIDCToken, nil
}
