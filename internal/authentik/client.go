/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authentik

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	api "goauthentik.io/api/v3"
)

// Client wraps the Authentik API client
type Client struct {
	api     *api.APIClient
	baseURL string
}

// NewClient creates a new Authentik API client
func NewClient(baseURL, token string, insecureSkipVerify bool, serviceURL string) *Client {
	// If serviceURL is provided, use it for API calls
	apiURL := baseURL
	if serviceURL != "" {
		apiURL = serviceURL
	}

	apiURL = strings.TrimSuffix(apiURL, "/")
	if !strings.HasSuffix(apiURL, "/api/v3") {
		apiURL = apiURL + "/api/v3"
	}

	cfg := api.NewConfiguration()
	cfg.Servers = api.ServerConfigurations{
		{URL: apiURL},
	}
	cfg.AddDefaultHeader("Authorization", fmt.Sprintf("Bearer %s", token))

	if insecureSkipVerify {
		cfg.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}

	return &Client{
		api:     api.NewAPIClient(cfg),
		baseURL: baseURL,
	}
}

// GetAuthorizationFlow returns the default authorization flow for OAuth2
func (c *Client) GetAuthorizationFlow(ctx context.Context) (*api.Flow, error) {
	designation := "authorization"
	flows, _, err := c.api.FlowsApi.FlowsInstancesList(ctx).Designation(designation).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to list flows: %w", err)
	}

	if len(flows.Results) == 0 {
		return nil, fmt.Errorf("no authorization flow found")
	}

	return &flows.Results[0], nil
}

// GetInvalidationFlow returns the default invalidation flow
func (c *Client) GetInvalidationFlow(ctx context.Context) (*api.Flow, error) {
	designation := "invalidation"
	flows, _, err := c.api.FlowsApi.FlowsInstancesList(ctx).Designation(designation).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to list flows: %w", err)
	}

	if len(flows.Results) == 0 {
		return nil, fmt.Errorf("no invalidation flow found")
	}

	return &flows.Results[0], nil
}

// GetScopeMappings returns the property mapping UUIDs for OAuth2 scopes
func (c *Client) GetScopeMappings(ctx context.Context, scopes []string) ([]string, error) {
	mappings, _, err := c.api.PropertymappingsApi.PropertymappingsProviderScopeList(ctx).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to list scope mappings: %w", err)
	}

	scopeSet := make(map[string]bool)
	for _, scope := range scopes {
		scopeSet[strings.ToLower(scope)] = true
	}

	var mappingIDs []string
	for _, mapping := range mappings.Results {
		scopeName := mapping.GetScopeName()
		if scopeSet[strings.ToLower(scopeName)] {
			mappingIDs = append(mappingIDs, mapping.GetPk())
		}
	}

	return mappingIDs, nil
}

// buildRedirectURIs converts string URIs to RedirectURIRequest slice
func buildRedirectURIs(uris []string) []api.RedirectURIRequest {
	result := make([]api.RedirectURIRequest, len(uris))
	for i, uri := range uris {
		result[i] = *api.NewRedirectURIRequest(api.MATCHINGMODEENUM_STRICT, uri)
	}
	return result
}

// CreateOAuth2Provider creates a new OAuth2 provider
func (c *Client) CreateOAuth2Provider(ctx context.Context, name, authFlowUUID, invalidationFlowUUID string, redirectURIs []string, clientType string, propertyMappings []string) (*api.OAuth2Provider, error) {
	redirectURIRequests := buildRedirectURIs(redirectURIs)
	req := api.NewOAuth2ProviderRequest(name, authFlowUUID, invalidationFlowUUID, redirectURIRequests)

	if clientType == "public" {
		req.SetClientType(api.CLIENTTYPEENUM_PUBLIC)
	} else {
		req.SetClientType(api.CLIENTTYPEENUM_CONFIDENTIAL)
	}

	// Always set property mappings, even if empty, to ensure proper API behavior
	req.SetPropertyMappings(propertyMappings)

	provider, resp, err := c.api.ProvidersApi.ProvidersOauth2Create(ctx).OAuth2ProviderRequest(*req).Execute()
	if err != nil {
		// Try to extract response body if available
		var errorMsg string
		if resp != nil && resp.Body != nil {
			if body, readErr := io.ReadAll(resp.Body); readErr == nil {
				errorMsg = fmt.Sprintf(" (response body: %s)", string(body))
				resp.Body.Close()
			}
		}
		// Include the original error which may already contain response details
		return nil, fmt.Errorf("failed to create OAuth2 provider: %w%s", err, errorMsg)
	}

	return provider, nil
}

// GetOAuth2Provider gets an OAuth2 provider by ID
func (c *Client) GetOAuth2Provider(ctx context.Context, id int32) (*api.OAuth2Provider, error) {
	provider, _, err := c.api.ProvidersApi.ProvidersOauth2Retrieve(ctx, id).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth2 provider: %w", err)
	}

	return provider, nil
}

// GetOAuth2ProviderByName searches for an OAuth2 provider by name
func (c *Client) GetOAuth2ProviderByName(ctx context.Context, name string) (*api.OAuth2Provider, error) {
	providers, _, err := c.api.ProvidersApi.ProvidersOauth2List(ctx).Search(name).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to list OAuth2 providers: %w", err)
	}

	for _, provider := range providers.Results {
		if provider.Name == name {
			return &provider, nil
		}
	}

	return nil, nil
}

// UpdateOAuth2Provider updates an existing OAuth2 provider
func (c *Client) UpdateOAuth2Provider(ctx context.Context, id int32, name, authFlowUUID, invalidationFlowUUID string, redirectURIs []string, clientType string, propertyMappings []string) (*api.OAuth2Provider, error) {
	redirectURIRequests := buildRedirectURIs(redirectURIs)
	req := api.NewOAuth2ProviderRequest(name, authFlowUUID, invalidationFlowUUID, redirectURIRequests)

	if clientType == "public" {
		req.SetClientType(api.CLIENTTYPEENUM_PUBLIC)
	} else {
		req.SetClientType(api.CLIENTTYPEENUM_CONFIDENTIAL)
	}

	// Always set property mappings, even if empty, to ensure proper API behavior
	req.SetPropertyMappings(propertyMappings)

	provider, _, err := c.api.ProvidersApi.ProvidersOauth2Update(ctx, id).OAuth2ProviderRequest(*req).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to update OAuth2 provider: %w", err)
	}

	return provider, nil
}

// DeleteOAuth2Provider deletes an OAuth2 provider
func (c *Client) DeleteOAuth2Provider(ctx context.Context, id int32) error {
	_, err := c.api.ProvidersApi.ProvidersOauth2Destroy(ctx, id).Execute()
	if err != nil {
		return fmt.Errorf("failed to delete OAuth2 provider: %w", err)
	}

	return nil
}

// CreateApplication creates a new application
func (c *Client) CreateApplication(ctx context.Context, slug, name string, providerID int32) (*api.Application, error) {
	req := api.NewApplicationRequest(name, slug)
	req.SetProvider(providerID)
	req.SetPolicyEngineMode(api.POLICYENGINEMODE_ANY)

	app, _, err := c.api.CoreApi.CoreApplicationsCreate(ctx).ApplicationRequest(*req).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to create application: %w", err)
	}

	return app, nil
}

// GetApplication gets an application by slug
func (c *Client) GetApplication(ctx context.Context, slug string) (*api.Application, error) {
	app, _, err := c.api.CoreApi.CoreApplicationsRetrieve(ctx, slug).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to get application: %w", err)
	}

	return app, nil
}

// GetApplicationBySlug searches for an application by slug
func (c *Client) GetApplicationBySlug(ctx context.Context, slug string) (*api.Application, error) {
	apps, _, err := c.api.CoreApi.CoreApplicationsList(ctx).Search(slug).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to list applications: %w", err)
	}

	for _, app := range apps.Results {
		if app.Slug == slug {
			return &app, nil
		}
	}

	return nil, nil
}

// UpdateApplication updates an existing application
func (c *Client) UpdateApplication(ctx context.Context, slug, name string, providerID int32) (*api.Application, error) {
	req := api.NewApplicationRequest(name, slug)
	req.SetProvider(providerID)
	req.SetPolicyEngineMode(api.POLICYENGINEMODE_ANY)

	app, _, err := c.api.CoreApi.CoreApplicationsUpdate(ctx, slug).ApplicationRequest(*req).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to update application: %w", err)
	}

	return app, nil
}

// DeleteApplication deletes an application
func (c *Client) DeleteApplication(ctx context.Context, slug string) error {
	_, err := c.api.CoreApi.CoreApplicationsDestroy(ctx, slug).Execute()
	if err != nil {
		return fmt.Errorf("failed to delete application: %w", err)
	}

	return nil
}

// HealthCheck checks if the Authentik API is available
func (c *Client) HealthCheck(ctx context.Context) error {
	_, _, err := c.api.CoreApi.CoreApplicationsList(ctx).PageSize(1).Execute()
	return err
}

// GetBaseURL returns the base URL of the Authentik server
func (c *Client) GetBaseURL() string {
	return c.baseURL
}
