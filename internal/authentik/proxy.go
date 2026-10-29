package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const embeddedOutpostManaged = "goauthentik.io/outposts/embedded"

// ProxyProvider holds the forward-auth provider fields the operator owns.
type ProxyProvider struct {
	PK                      int32  `json:"pk,omitempty"`
	Name                    string `json:"name"`
	AuthorizationFlow       string `json:"authorization_flow"`
	InvalidationFlow        string `json:"invalidation_flow"`
	ExternalHost            string `json:"external_host"`
	Mode                    string `json:"mode"`
	AccessTokenValidity     string `json:"access_token_validity"`
	AssignedApplicationSlug string `json:"assigned_application_slug,omitempty"`
}

// ProxyPlan identifies a proxy provider. KnownID is the provider recorded in
// Kubernetes status; AppSlug is the owned application it may be attached to.
type ProxyPlan struct {
	Desired ProxyProvider
	KnownID int32
	AppSlug string
}

type outpost struct {
	PK        string         `json:"pk"`
	Name      string         `json:"name"`
	Managed   string         `json:"managed"`
	Providers []int32        `json:"providers"`
	Config    map[string]any `json:"config"`
}

func proxyMatches(a, b ProxyProvider) bool {
	return a.Name == b.Name && a.AuthorizationFlow == b.AuthorizationFlow && a.InvalidationFlow == b.InvalidationFlow &&
		a.ExternalHost == b.ExternalHost && a.Mode == b.Mode && a.AccessTokenValidity == b.AccessTokenValidity
}

// ReconcileProxyProvider creates or repairs the proxy provider. Only a provider
// this resource created (its persisted ID) is ever modified; a provider that
// merely has the desired name is a conflict and is never adopted.
func (c *Client) ReconcileProxyProvider(ctx context.Context, plan ProxyPlan) (*ProxyProvider, error) {
	desired := plan.Desired
	var current *ProxyProvider
	if plan.KnownID > 0 {
		var p ProxyProvider
		err := c.managedRequest(ctx, http.MethodGet, fmt.Sprintf("providers/proxy/%d/", plan.KnownID), nil, &p)
		if err != nil && !isManagedNotFound(err) {
			return nil, err
		}
		if err == nil {
			if p.AssignedApplicationSlug != "" && p.AssignedApplicationSlug != plan.AppSlug {
				return nil, fmt.Errorf("recorded proxy provider is assigned to another application; refusing to modify it")
			}
			current = &p
		}
	}
	if current == nil {
		found, err := managedList[ProxyProvider](ctx, c, "providers/proxy/?name__iexact="+url.QueryEscape(desired.Name))
		if err != nil {
			return nil, err
		}
		for _, p := range found {
			if strings.EqualFold(p.Name, desired.Name) {
				return nil, fmt.Errorf("a proxy provider named %s already exists and is not recorded as owned; refusing adoption", desired.Name)
			}
		}
	}
	var result ProxyProvider
	switch {
	case current == nil:
		if err := c.managedRequest(ctx, http.MethodPost, "providers/proxy/", desired, &result); err != nil {
			return nil, err
		}
	case !proxyMatches(*current, desired):
		if err := c.managedRequest(ctx, http.MethodPatch, fmt.Sprintf("providers/proxy/%d/", current.PK), desired, &result); err != nil {
			return nil, err
		}
	default:
		return current, nil
	}
	if result.PK == 0 || !proxyMatches(result, desired) {
		return nil, fmt.Errorf("proxy provider verification failed")
	}
	return &result, nil
}

// DeleteProxyProvider removes a provider; an already missing provider is success.
func (c *Client) DeleteProxyProvider(ctx context.Context, id int32) error {
	err := c.managedRequest(ctx, http.MethodDelete, fmt.Sprintf("providers/proxy/%d/", id), nil, nil)
	if isManagedNotFound(err) {
		return nil
	}
	return err
}

// DeleteOwnedApplication removes an application only while it still carries
// this owner's claim; a missing application is success.
func (c *Client) DeleteOwnedApplication(ctx context.Context, slug, owner string) error {
	path := "core/applications/" + url.PathEscape(slug) + "/"
	var app AccessApplication
	err := c.managedRequest(ctx, http.MethodGet, path, nil, &app)
	if isManagedNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if app.Description != applicationOwner(owner) {
		return fmt.Errorf("application %s is not owned by this resource; refusing deletion", slug)
	}
	err = c.managedRequest(ctx, http.MethodDelete, path, nil, nil)
	if isManagedNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) embeddedOutpost(ctx context.Context) (*outpost, error) {
	found, err := managedList[outpost](ctx, c, "outposts/instances/?managed__iexact="+url.QueryEscape(embeddedOutpostManaged))
	if err != nil {
		return nil, err
	}
	var result *outpost
	for i := range found {
		if found[i].Managed == embeddedOutpostManaged {
			if result != nil {
				return nil, fmt.Errorf("ambiguous embedded outpost")
			}
			result = &found[i]
		}
	}
	if result == nil {
		return nil, fmt.Errorf("embedded outpost not found")
	}
	return result, nil
}

// updateEmbeddedOutpost applies a change to the embedded outpost's provider list
// and authentik_host, then reads back the result. Providers the operator does
// not own are carried over untouched; only the given provider is added/removed.
func (c *Client) updateEmbeddedOutpost(ctx context.Context, providerID int32, attach bool, authentikHost string) (string, error) {
	o, err := c.embeddedOutpost(ctx)
	if err != nil {
		return "", err
	}
	verify := func(o *outpost) bool {
		if slices.Contains(o.Providers, providerID) != attach {
			return false
		}
		return authentikHost == "" || o.Config["authentik_host"] == authentikHost
	}
	if verify(o) {
		return o.PK, nil
	}
	providers := slices.DeleteFunc(slices.Clone(o.Providers), func(id int32) bool { return id == providerID })
	if attach {
		providers = append(providers, providerID)
	}
	patch := map[string]any{"providers": providers}
	if authentikHost != "" {
		config := map[string]any{}
		for k, v := range o.Config {
			config[k] = v
		}
		config["authentik_host"] = authentikHost
		patch["config"] = config
	}
	path := "outposts/instances/" + url.PathEscape(o.PK) + "/"
	if err := c.managedRequest(ctx, http.MethodPatch, path, patch, nil); err != nil {
		return "", err
	}
	var persisted outpost
	if err := c.managedRequest(ctx, http.MethodGet, path, nil, &persisted); err != nil {
		return "", err
	}
	if !verify(&persisted) {
		return "", fmt.Errorf("embedded outpost update verification failed")
	}
	return persisted.PK, nil
}

// AttachToEmbeddedOutpost serves the provider from the embedded outpost and sets
// the browser-facing Authentik URL the outpost redirects to.
func (c *Client) AttachToEmbeddedOutpost(ctx context.Context, providerID int32, authentikHost string) (string, error) {
	if providerID == 0 || authentikHost == "" {
		return "", fmt.Errorf("provider and authentik host required")
	}
	return c.updateEmbeddedOutpost(ctx, providerID, true, authentikHost)
}

// DetachFromEmbeddedOutpost stops serving the provider.
func (c *Client) DetachFromEmbeddedOutpost(ctx context.Context, providerID int32) error {
	_, err := c.updateEmbeddedOutpost(ctx, providerID, false, "")
	return err
}
