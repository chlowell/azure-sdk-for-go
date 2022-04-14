//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armsaas

import (
	"encoding/json"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"reflect"
)

// MarshalJSON implements the json.Marshaller interface for type App.
func (a App) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "id", a.ID)
	populate(objectMap, "location", a.Location)
	populate(objectMap, "name", a.Name)
	populate(objectMap, "properties", a.Properties)
	populate(objectMap, "tags", a.Tags)
	populate(objectMap, "type", a.Type)
	return json.Marshal(objectMap)
}

// MarshalJSON implements the json.Marshaller interface for type AppOperationsResponseWithContinuation.
func (a AppOperationsResponseWithContinuation) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "nextLink", a.NextLink)
	populate(objectMap, "value", a.Value)
	return json.Marshal(objectMap)
}

// MarshalJSON implements the json.Marshaller interface for type AppResponseWithContinuation.
func (a AppResponseWithContinuation) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "nextLink", a.NextLink)
	populate(objectMap, "value", a.Value)
	return json.Marshal(objectMap)
}

// MarshalJSON implements the json.Marshaller interface for type CreationProperties.
func (c CreationProperties) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "autoRenew", c.AutoRenew)
	populate(objectMap, "offerId", c.OfferID)
	populate(objectMap, "paymentChannelMetadata", c.PaymentChannelMetadata)
	populate(objectMap, "paymentChannelType", c.PaymentChannelType)
	populate(objectMap, "publisherId", c.PublisherID)
	populate(objectMap, "publisherTestEnvironment", c.PublisherTestEnvironment)
	populate(objectMap, "quantity", c.Quantity)
	populate(objectMap, "skuId", c.SKUID)
	populate(objectMap, "saasResourceName", c.SaasResourceName)
	populate(objectMap, "saasSessionId", c.SaasSessionID)
	populate(objectMap, "saasSubscriptionId", c.SaasSubscriptionID)
	populate(objectMap, "termId", c.TermID)
	return json.Marshal(objectMap)
}

// MarshalJSON implements the json.Marshaller interface for type ErrorDetail.
func (e ErrorDetail) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "additionalInfo", e.AdditionalInfo)
	populate(objectMap, "code", e.Code)
	populate(objectMap, "details", e.Details)
	populate(objectMap, "message", e.Message)
	populate(objectMap, "target", e.Target)
	return json.Marshal(objectMap)
}

// MarshalJSON implements the json.Marshaller interface for type MoveResource.
func (m MoveResource) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "resources", m.Resources)
	populate(objectMap, "targetResourceGroup", m.TargetResourceGroup)
	return json.Marshal(objectMap)
}

// MarshalJSON implements the json.Marshaller interface for type Resource.
func (r Resource) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "id", r.ID)
	populate(objectMap, "name", r.Name)
	populate(objectMap, "properties", r.Properties)
	populate(objectMap, "tags", r.Tags)
	populate(objectMap, "type", r.Type)
	return json.Marshal(objectMap)
}

// MarshalJSON implements the json.Marshaller interface for type ResourceCreation.
func (r ResourceCreation) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "id", r.ID)
	populate(objectMap, "location", r.Location)
	populate(objectMap, "name", r.Name)
	populate(objectMap, "properties", r.Properties)
	populate(objectMap, "tags", r.Tags)
	populate(objectMap, "type", r.Type)
	return json.Marshal(objectMap)
}

// MarshalJSON implements the json.Marshaller interface for type ResourceProperties.
func (r ResourceProperties) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "autoRenew", r.AutoRenew)
	populate(objectMap, "created", r.Created)
	populate(objectMap, "isFreeTrial", r.IsFreeTrial)
	populate(objectMap, "lastModified", r.LastModified)
	populate(objectMap, "offerId", r.OfferID)
	populate(objectMap, "paymentChannelMetadata", r.PaymentChannelMetadata)
	populate(objectMap, "paymentChannelType", r.PaymentChannelType)
	populate(objectMap, "publisherId", r.PublisherID)
	populate(objectMap, "publisherTestEnvironment", r.PublisherTestEnvironment)
	populate(objectMap, "quantity", r.Quantity)
	populate(objectMap, "skuId", r.SKUID)
	populate(objectMap, "saasResourceName", r.SaasResourceName)
	populate(objectMap, "saasSessionId", r.SaasSessionID)
	populate(objectMap, "saasSubscriptionId", r.SaasSubscriptionID)
	populate(objectMap, "status", r.Status)
	populate(objectMap, "term", r.Term)
	populate(objectMap, "termId", r.TermID)
	return json.Marshal(objectMap)
}

// MarshalJSON implements the json.Marshaller interface for type ResourceResponseWithContinuation.
func (r ResourceResponseWithContinuation) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "nextLink", r.NextLink)
	populate(objectMap, "value", r.Value)
	return json.Marshal(objectMap)
}

func populate(m map[string]interface{}, k string, v interface{}) {
	if v == nil {
		return
	} else if azcore.IsNullValue(v) {
		m[k] = nil
	} else if !reflect.ValueOf(v).IsNil() {
		m[k] = v
	}
}