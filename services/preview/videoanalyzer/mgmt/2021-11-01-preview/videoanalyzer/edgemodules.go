package videoanalyzer

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"context"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/validation"
	"github.com/Azure/go-autorest/tracing"
	"net/http"
)

// EdgeModulesClient is the azure Video Analyzer provides a platform for you to build intelligent video applications
// that span the edge and the cloud
type EdgeModulesClient struct {
	BaseClient
}

// NewEdgeModulesClient creates an instance of the EdgeModulesClient client.
func NewEdgeModulesClient(subscriptionID string) EdgeModulesClient {
	return NewEdgeModulesClientWithBaseURI(DefaultBaseURI, subscriptionID)
}

// NewEdgeModulesClientWithBaseURI creates an instance of the EdgeModulesClient client using a custom endpoint.  Use
// this when interacting with an Azure cloud that uses a non-standard base URI (sovereign clouds, Azure stack).
func NewEdgeModulesClientWithBaseURI(baseURI string, subscriptionID string) EdgeModulesClient {
	return EdgeModulesClient{NewWithBaseURI(baseURI, subscriptionID)}
}

// CreateOrUpdate creates a new edge module or updates an existing one. An edge module resource enables a single
// instance of an Azure Video Analyzer IoT edge module to interact with the Video Analyzer Account. This is used for
// authorization and also to make sure that the particular edge module instance only has access to the data it requires
// from the Azure Video Analyzer service. A new edge module resource should be created for every new instance of an
// Azure Video Analyzer edge module deployed to you Azure IoT edge environment. Edge module resources can be deleted if
// the specific module is not in use anymore.
// Parameters:
// resourceGroupName - the name of the resource group. The name is case insensitive.
// accountName - the Azure Video Analyzer account name.
// edgeModuleName - the Edge Module name.
// parameters - the request parameters
func (client EdgeModulesClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, accountName string, edgeModuleName string, parameters EdgeModuleEntity) (result EdgeModuleEntity, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/EdgeModulesClient.CreateOrUpdate")
		defer func() {
			sc := -1
			if result.Response.Response != nil {
				sc = result.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: client.SubscriptionID,
			Constraints: []validation.Constraint{{Target: "client.SubscriptionID", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: resourceGroupName,
			Constraints: []validation.Constraint{{Target: "resourceGroupName", Name: validation.MaxLength, Rule: 90, Chain: nil},
				{Target: "resourceGroupName", Name: validation.MinLength, Rule: 1, Chain: nil}}}}); err != nil {
		return result, validation.NewError("videoanalyzer.EdgeModulesClient", "CreateOrUpdate", err.Error())
	}

	req, err := client.CreateOrUpdatePreparer(ctx, resourceGroupName, accountName, edgeModuleName, parameters)
	if err != nil {
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "CreateOrUpdate", nil, "Failure preparing request")
		return
	}

	resp, err := client.CreateOrUpdateSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "CreateOrUpdate", resp, "Failure sending request")
		return
	}

	result, err = client.CreateOrUpdateResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "CreateOrUpdate", resp, "Failure responding to request")
		return
	}

	return
}

// CreateOrUpdatePreparer prepares the CreateOrUpdate request.
func (client EdgeModulesClient) CreateOrUpdatePreparer(ctx context.Context, resourceGroupName string, accountName string, edgeModuleName string, parameters EdgeModuleEntity) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"accountName":       autorest.Encode("path", accountName),
		"edgeModuleName":    autorest.Encode("path", edgeModuleName),
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2021-11-01-preview"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPut(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/videoAnalyzers/{accountName}/edgeModules/{edgeModuleName}", pathParameters),
		autorest.WithJSON(parameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// CreateOrUpdateSender sends the CreateOrUpdate request. The method will close the
// http.Response Body if it receives an error.
func (client EdgeModulesClient) CreateOrUpdateSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, azure.DoRetryWithRegistration(client.Client))
}

// CreateOrUpdateResponder handles the response to the CreateOrUpdate request. The method always
// closes the http.Response Body.
func (client EdgeModulesClient) CreateOrUpdateResponder(resp *http.Response) (result EdgeModuleEntity, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusCreated),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// Delete deletes an existing edge module resource. Deleting the edge module resource will prevent an Azure Video
// Analyzer IoT edge module which was previously initiated with the module provisioning token from communicating with
// the cloud.
// Parameters:
// resourceGroupName - the name of the resource group. The name is case insensitive.
// accountName - the Azure Video Analyzer account name.
// edgeModuleName - the Edge Module name.
func (client EdgeModulesClient) Delete(ctx context.Context, resourceGroupName string, accountName string, edgeModuleName string) (result autorest.Response, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/EdgeModulesClient.Delete")
		defer func() {
			sc := -1
			if result.Response != nil {
				sc = result.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: client.SubscriptionID,
			Constraints: []validation.Constraint{{Target: "client.SubscriptionID", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: resourceGroupName,
			Constraints: []validation.Constraint{{Target: "resourceGroupName", Name: validation.MaxLength, Rule: 90, Chain: nil},
				{Target: "resourceGroupName", Name: validation.MinLength, Rule: 1, Chain: nil}}}}); err != nil {
		return result, validation.NewError("videoanalyzer.EdgeModulesClient", "Delete", err.Error())
	}

	req, err := client.DeletePreparer(ctx, resourceGroupName, accountName, edgeModuleName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "Delete", nil, "Failure preparing request")
		return
	}

	resp, err := client.DeleteSender(req)
	if err != nil {
		result.Response = resp
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "Delete", resp, "Failure sending request")
		return
	}

	result, err = client.DeleteResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "Delete", resp, "Failure responding to request")
		return
	}

	return
}

// DeletePreparer prepares the Delete request.
func (client EdgeModulesClient) DeletePreparer(ctx context.Context, resourceGroupName string, accountName string, edgeModuleName string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"accountName":       autorest.Encode("path", accountName),
		"edgeModuleName":    autorest.Encode("path", edgeModuleName),
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2021-11-01-preview"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsDelete(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/videoAnalyzers/{accountName}/edgeModules/{edgeModuleName}", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// DeleteSender sends the Delete request. The method will close the
// http.Response Body if it receives an error.
func (client EdgeModulesClient) DeleteSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, azure.DoRetryWithRegistration(client.Client))
}

// DeleteResponder handles the response to the Delete request. The method always
// closes the http.Response Body.
func (client EdgeModulesClient) DeleteResponder(resp *http.Response) (result autorest.Response, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusNoContent),
		autorest.ByClosing())
	result.Response = resp
	return
}

// Get retrieves an existing edge module resource with the given name.
// Parameters:
// resourceGroupName - the name of the resource group. The name is case insensitive.
// accountName - the Azure Video Analyzer account name.
// edgeModuleName - the Edge Module name.
func (client EdgeModulesClient) Get(ctx context.Context, resourceGroupName string, accountName string, edgeModuleName string) (result EdgeModuleEntity, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/EdgeModulesClient.Get")
		defer func() {
			sc := -1
			if result.Response.Response != nil {
				sc = result.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: client.SubscriptionID,
			Constraints: []validation.Constraint{{Target: "client.SubscriptionID", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: resourceGroupName,
			Constraints: []validation.Constraint{{Target: "resourceGroupName", Name: validation.MaxLength, Rule: 90, Chain: nil},
				{Target: "resourceGroupName", Name: validation.MinLength, Rule: 1, Chain: nil}}}}); err != nil {
		return result, validation.NewError("videoanalyzer.EdgeModulesClient", "Get", err.Error())
	}

	req, err := client.GetPreparer(ctx, resourceGroupName, accountName, edgeModuleName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "Get", nil, "Failure preparing request")
		return
	}

	resp, err := client.GetSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "Get", resp, "Failure sending request")
		return
	}

	result, err = client.GetResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "Get", resp, "Failure responding to request")
		return
	}

	return
}

// GetPreparer prepares the Get request.
func (client EdgeModulesClient) GetPreparer(ctx context.Context, resourceGroupName string, accountName string, edgeModuleName string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"accountName":       autorest.Encode("path", accountName),
		"edgeModuleName":    autorest.Encode("path", edgeModuleName),
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2021-11-01-preview"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/videoAnalyzers/{accountName}/edgeModules/{edgeModuleName}", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// GetSender sends the Get request. The method will close the
// http.Response Body if it receives an error.
func (client EdgeModulesClient) GetSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, azure.DoRetryWithRegistration(client.Client))
}

// GetResponder handles the response to the Get request. The method always
// closes the http.Response Body.
func (client EdgeModulesClient) GetResponder(resp *http.Response) (result EdgeModuleEntity, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// List list all existing edge module resources, along with their JSON representations.
// Parameters:
// resourceGroupName - the name of the resource group. The name is case insensitive.
// accountName - the Azure Video Analyzer account name.
// top - specifies a non-negative integer n that limits the number of items returned from a collection. The
// service returns the number of available items up to but not greater than the specified value n.
func (client EdgeModulesClient) List(ctx context.Context, resourceGroupName string, accountName string, top *int32) (result EdgeModuleEntityCollectionPage, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/EdgeModulesClient.List")
		defer func() {
			sc := -1
			if result.emec.Response.Response != nil {
				sc = result.emec.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: client.SubscriptionID,
			Constraints: []validation.Constraint{{Target: "client.SubscriptionID", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: resourceGroupName,
			Constraints: []validation.Constraint{{Target: "resourceGroupName", Name: validation.MaxLength, Rule: 90, Chain: nil},
				{Target: "resourceGroupName", Name: validation.MinLength, Rule: 1, Chain: nil}}}}); err != nil {
		return result, validation.NewError("videoanalyzer.EdgeModulesClient", "List", err.Error())
	}

	result.fn = client.listNextResults
	req, err := client.ListPreparer(ctx, resourceGroupName, accountName, top)
	if err != nil {
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "List", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListSender(req)
	if err != nil {
		result.emec.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "List", resp, "Failure sending request")
		return
	}

	result.emec, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "List", resp, "Failure responding to request")
		return
	}
	if result.emec.hasNextLink() && result.emec.IsEmpty() {
		err = result.NextWithContext(ctx)
		return
	}

	return
}

// ListPreparer prepares the List request.
func (client EdgeModulesClient) ListPreparer(ctx context.Context, resourceGroupName string, accountName string, top *int32) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"accountName":       autorest.Encode("path", accountName),
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2021-11-01-preview"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}
	if top != nil {
		queryParameters["$top"] = autorest.Encode("query", *top)
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/videoAnalyzers/{accountName}/edgeModules", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// ListSender sends the List request. The method will close the
// http.Response Body if it receives an error.
func (client EdgeModulesClient) ListSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, azure.DoRetryWithRegistration(client.Client))
}

// ListResponder handles the response to the List request. The method always
// closes the http.Response Body.
func (client EdgeModulesClient) ListResponder(resp *http.Response) (result EdgeModuleEntityCollection, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// listNextResults retrieves the next set of results, if any.
func (client EdgeModulesClient) listNextResults(ctx context.Context, lastResults EdgeModuleEntityCollection) (result EdgeModuleEntityCollection, err error) {
	req, err := lastResults.edgeModuleEntityCollectionPreparer(ctx)
	if err != nil {
		return result, autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "listNextResults", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}
	resp, err := client.ListSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "listNextResults", resp, "Failure sending next results request")
	}
	result, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "listNextResults", resp, "Failure responding to next results request")
	}
	return
}

// ListComplete enumerates all values, automatically crossing page boundaries as required.
func (client EdgeModulesClient) ListComplete(ctx context.Context, resourceGroupName string, accountName string, top *int32) (result EdgeModuleEntityCollectionIterator, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/EdgeModulesClient.List")
		defer func() {
			sc := -1
			if result.Response().Response.Response != nil {
				sc = result.page.Response().Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	result.page, err = client.List(ctx, resourceGroupName, accountName, top)
	return
}

// ListProvisioningToken creates a new provisioning token. A provisioning token allows for a single instance of Azure
// Video analyzer IoT edge module to be initialized and authorized to the cloud account. The provisioning token itself
// is short lived and it is only used for the initial handshake between IoT edge module and the cloud. After the
// initial handshake, the IoT edge module will agree on a set of authentication keys which will be auto-rotated as long
// as the module is able to periodically connect to the cloud. A new provisioning token can be generated for the same
// IoT edge module in case the module state lost or reset.
// Parameters:
// resourceGroupName - the name of the resource group. The name is case insensitive.
// accountName - the Azure Video Analyzer account name.
// edgeModuleName - the Edge Module name.
// parameters - the request parameters
func (client EdgeModulesClient) ListProvisioningToken(ctx context.Context, resourceGroupName string, accountName string, edgeModuleName string, parameters ListProvisioningTokenInput) (result EdgeModuleProvisioningToken, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/EdgeModulesClient.ListProvisioningToken")
		defer func() {
			sc := -1
			if result.Response.Response != nil {
				sc = result.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: client.SubscriptionID,
			Constraints: []validation.Constraint{{Target: "client.SubscriptionID", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: resourceGroupName,
			Constraints: []validation.Constraint{{Target: "resourceGroupName", Name: validation.MaxLength, Rule: 90, Chain: nil},
				{Target: "resourceGroupName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: parameters,
			Constraints: []validation.Constraint{{Target: "parameters.ExpirationDate", Name: validation.Null, Rule: true, Chain: nil}}}}); err != nil {
		return result, validation.NewError("videoanalyzer.EdgeModulesClient", "ListProvisioningToken", err.Error())
	}

	req, err := client.ListProvisioningTokenPreparer(ctx, resourceGroupName, accountName, edgeModuleName, parameters)
	if err != nil {
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "ListProvisioningToken", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListProvisioningTokenSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "ListProvisioningToken", resp, "Failure sending request")
		return
	}

	result, err = client.ListProvisioningTokenResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "videoanalyzer.EdgeModulesClient", "ListProvisioningToken", resp, "Failure responding to request")
		return
	}

	return
}

// ListProvisioningTokenPreparer prepares the ListProvisioningToken request.
func (client EdgeModulesClient) ListProvisioningTokenPreparer(ctx context.Context, resourceGroupName string, accountName string, edgeModuleName string, parameters ListProvisioningTokenInput) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"accountName":       autorest.Encode("path", accountName),
		"edgeModuleName":    autorest.Encode("path", edgeModuleName),
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2021-11-01-preview"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/videoAnalyzers/{accountName}/edgeModules/{edgeModuleName}/listProvisioningToken", pathParameters),
		autorest.WithJSON(parameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// ListProvisioningTokenSender sends the ListProvisioningToken request. The method will close the
// http.Response Body if it receives an error.
func (client EdgeModulesClient) ListProvisioningTokenSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, azure.DoRetryWithRegistration(client.Client))
}

// ListProvisioningTokenResponder handles the response to the ListProvisioningToken request. The method always
// closes the http.Response Body.
func (client EdgeModulesClient) ListProvisioningTokenResponder(resp *http.Response) (result EdgeModuleProvisioningToken, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}
