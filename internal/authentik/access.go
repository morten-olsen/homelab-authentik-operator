package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
)

const accessModeAny = "any"
const accessModeAll = "all"

type AccessApplication struct {
	PK          string `json:"pk"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Provider    int32  `json:"provider"`
	Mode        string `json:"policy_engine_mode"`
	Description string `json:"meta_description"`
}
type AccessBinding struct {
	PK            string  `json:"pk,omitempty"`
	Target        string  `json:"target"`
	Group         string  `json:"group,omitempty"`
	Policy        string  `json:"policy,omitempty"`
	User          int32   `json:"user,omitempty"`
	Enabled       bool    `json:"enabled"`
	Negate        bool    `json:"negate"`
	FailureResult bool    `json:"failure_result"`
	Order         int     `json:"order"`
	Expiring      bool    `json:"expiring"`
	Expires       *string `json:"expires"`
}
type GuardPolicy struct {
	PK               string `json:"pk,omitempty"`
	Name             string `json:"name"`
	Expression       string `json:"expression"`
	ExecutionLogging bool   `json:"execution_logging"`
}
type AccessPlan struct {
	Slug, Name, Owner string
	ProviderID        int32
	ClaimExisting     bool
	Groups            []GroupIdentity
	ResolutionError   error
	ReplacesBindings  []string
}

func applicationOwner(owner string) string { return "Managed by AuthentikClient " + owner }
func guardExpression(owner string) string {
	return "# AuthentikClient owner: " + owner + "\nreturn False"
}

func (c *Client) guardPolicy(ctx context.Context, owner string) (*GuardPolicy, error) {
	name := "gitops/client/" + owner
	policies, err := managedList[GuardPolicy](ctx, c, "policies/expression/?name="+url.QueryEscape(name))
	if err != nil {
		return nil, err
	}
	var guard *GuardPolicy
	for i := range policies {
		if policies[i].Name == name {
			if guard != nil {
				return nil, fmt.Errorf("ambiguous access guard")
			}
			guard = &policies[i]
		}
	}
	desired := GuardPolicy{Name: name, Expression: guardExpression(owner)}
	if guard == nil {
		if err := c.managedRequest(ctx, http.MethodPost, "policies/expression/", desired, &desired); err != nil {
			return nil, err
		}
		if desired.PK == "" || desired.Name != name || desired.Expression != guardExpression(owner) || desired.ExecutionLogging {
			return nil, fmt.Errorf("access guard verification failed")
		}
		return &desired, nil
	}
	// The UID in both name and expression is the ownership claim. An expression
	// edited in the UI is drift on this managed policy, repaired to constant false.
	if guard.Expression != desired.Expression || guard.ExecutionLogging {
		desired.PK = guard.PK
		if err := c.managedRequest(ctx, http.MethodPut, "policies/expression/"+url.PathEscape(guard.PK)+"/", desired, &desired); err != nil {
			return nil, err
		}
		if desired.PK == "" || desired.Name != name || desired.Expression != guardExpression(owner) || desired.ExecutionLogging {
			return nil, fmt.Errorf("access guard verification failed")
		}
		return &desired, nil
	}
	return guard, nil
}
func (c *Client) HasAccessGuard(ctx context.Context, owner string) (bool, error) {
	policies, err := managedList[GuardPolicy](ctx, c, "policies/expression/?name="+url.QueryEscape("gitops/client/"+owner))
	if err != nil {
		return false, err
	}
	for _, p := range policies {
		if p.Name == "gitops/client/"+owner {
			return true, nil
		}
	}
	return false, nil
}
func (c *Client) bindings(ctx context.Context, target string) ([]AccessBinding, error) {
	result, err := managedList[AccessBinding](ctx, c, "policies/bindings/?target="+url.QueryEscape(target))
	if err != nil {
		return nil, err
	}
	for _, b := range result {
		if b.Target != target {
			return nil, fmt.Errorf("unexpected binding target")
		}
	}
	return result, nil
}
func canonicalBinding(b AccessBinding) bool {
	return b.Enabled && !b.Negate && !b.FailureResult && b.User == 0 && !b.Expiring && b.Expires == nil
}
func matchingAccess(bindings []AccessBinding, guard string, groups []GroupIdentity) bool {
	if len(bindings) != len(groups)+1 {
		return false
	}
	found := map[string]bool{}
	for _, b := range bindings {
		if !canonicalBinding(b) {
			return false
		}
		key := ""
		if b.Policy == guard && b.Group == "" {
			key = "guard"
		} else if b.Policy == "" && b.Group != "" {
			key = b.Group
		} else {
			return false
		}
		if found[key] {
			return false
		}
		found[key] = true
	}
	if !found["guard"] {
		return false
	}
	for _, g := range groups {
		if !found[g.ID] {
			return false
		}
	}
	return true
}
func (c *Client) accessMode(ctx context.Context, slug, mode string) error {
	return c.managedRequest(ctx, http.MethodPatch, "core/applications/"+url.PathEscape(slug)+"/", map[string]any{"policy_engine_mode": mode}, nil)
}

// ReconcileAccess changes binding sets behind an ALL + constant-false guard.
// The guard remains in ANY after success, so deleting the last allowed group
// cannot accidentally turn the application's empty binding set into allow-all.
// Existing binding deletion is explicitly inventoried; unexpected foreign
// bindings close the application and require a GitOps migration decision.
func (c *Client) ReconcileAccess(ctx context.Context, plan AccessPlan) (result *AccessApplication, reconcileErr error) {
	app, err := c.claimAccessApplication(ctx, plan)
	if err != nil {
		return nil, err
	}
	// Even errors before a guard can be read must not leave an owned provider
	// attached. A failed API write is reported, never described as fail-closed.
	defer func() {
		if reconcileErr != nil {
			if closeErr := c.managedRequest(ctx, http.MethodPatch, "core/applications/"+url.PathEscape(plan.Slug)+"/", map[string]any{"provider": nil, "policy_engine_mode": accessModeAll}, nil); closeErr != nil {
				reconcileErr = fmt.Errorf("%w; could not disconnect provider: %v", reconcileErr, closeErr)
			}
		}
	}()
	initiallyManaged := app.Description == applicationOwner(plan.Owner)
	guard, err := c.guardPolicy(ctx, plan.Owner)
	if err != nil {
		return nil, err
	}
	bindings, err := c.bindings(ctx, app.PK)
	if err != nil {
		return nil, err
	}
	resolutionErr := c.validateAccessGroups(ctx, plan)
	if resolutionErr == nil && app.Mode == accessModeAny && matchingAccess(bindings, guard.PK, plan.Groups) {
		return app, nil
	}
	guardBinding, err := c.lockAccess(ctx, plan.Slug, app.PK, guard.PK, bindings)
	if err != nil {
		return nil, err
	}
	if resolutionErr != nil {
		return nil, resolutionErr
	}
	if err := c.replaceAccessBindings(ctx, plan, app.PK, guard.PK, guardBinding, bindings, initiallyManaged); err != nil {
		return nil, err
	}
	if err := c.accessMode(ctx, plan.Slug, accessModeAny); err != nil {
		return nil, err
	}
	app.Mode = accessModeAny
	return app, nil
}
func (c *Client) ConnectApplication(ctx context.Context, slug, name string, providerID int32) error {
	return c.managedRequest(ctx, http.MethodPatch, "core/applications/"+url.PathEscape(slug)+"/", map[string]any{"name": name, "provider": providerID}, nil)
}

func (c *Client) claimAccessApplication(ctx context.Context, plan AccessPlan) (*AccessApplication, error) {
	if plan.Slug == "" || plan.Owner == "" {
		return nil, fmt.Errorf("application identity required")
	}
	var app AccessApplication
	err := c.managedRequest(ctx, http.MethodGet, "core/applications/"+url.PathEscape(plan.Slug)+"/", nil, &app)
	if err != nil && !isManagedNotFound(err) {
		return nil, err
	}
	if isManagedNotFound(err) {
		payload := map[string]any{"name": plan.Name, "slug": plan.Slug, "provider": nil, "policy_engine_mode": accessModeAll, "meta_description": applicationOwner(plan.Owner)}
		if err := c.managedRequest(ctx, http.MethodPost, "core/applications/", payload, &app); err != nil {
			return nil, err
		}
		if app.PK == "" || app.Slug != plan.Slug || app.Provider != 0 || app.Description != applicationOwner(plan.Owner) {
			return nil, fmt.Errorf("disconnected application creation verification failed")
		}
	} else if !plan.ClaimExisting && app.Description != applicationOwner(plan.Owner) {
		return nil, fmt.Errorf("existing application is not claimed by this client and provider; refusing adoption")
	}
	if err := c.recoverApplicationProvider(ctx, plan, &app); err != nil {
		return nil, err
	}
	return &app, nil
}

func (c *Client) recoverApplicationProvider(ctx context.Context, plan AccessPlan, app *AccessApplication) error {
	if app.Provider == 0 || app.Provider == plan.ProviderID {
		return nil
	}
	if plan.ProviderID != 0 || app.Description != applicationOwner(plan.Owner) {
		return fmt.Errorf("existing application is not claimed by this client and provider; refusing adoption")
	}
	// A lost/conflicted status write must not permanently strand a UID-owned
	// application. Do not infer ownership of its attached provider: disconnect
	// and verify closure, then let normal provider reconciliation select it.
	path := "core/applications/" + url.PathEscape(plan.Slug) + "/"
	if err := c.managedRequest(ctx, http.MethodPatch, path, map[string]any{"provider": nil, "policy_engine_mode": accessModeAll}, nil); err != nil {
		return err
	}
	var persisted AccessApplication
	if err := c.managedRequest(ctx, http.MethodGet, path, nil, &persisted); err != nil {
		return err
	}
	if persisted.PK != app.PK || persisted.Slug != plan.Slug || persisted.Description != applicationOwner(plan.Owner) || persisted.Provider != 0 || persisted.Mode != accessModeAll {
		return fmt.Errorf("owned application closure could not be verified after provider status loss")
	}
	*app = persisted
	return nil
}

func (c *Client) validateAccessGroups(ctx context.Context, plan AccessPlan) error {
	resolutionErr := plan.ResolutionError
	if len(plan.Groups) == 0 && resolutionErr == nil {
		resolutionErr = fmt.Errorf("at least one allowed group is required")
	}
	unique := map[string]bool{}
	for _, g := range plan.Groups {
		if unique[g.ID] {
			resolutionErr = fmt.Errorf("duplicate allowed group")
		}
		unique[g.ID] = true
		if err := c.ValidateGroup(ctx, g); err != nil {
			resolutionErr = err
		}
	}
	return resolutionErr
}
func (c *Client) lockAccess(ctx context.Context, slug, target, guardID string, bindings []AccessBinding) (string, error) {
	// Always retain a deny binding. Add a new guard before deleting any binding.
	guardBinding := ""
	for _, b := range bindings {
		if b.Policy == guardID && b.Group == "" && canonicalBinding(b) {
			guardBinding = b.PK
			break
		}
	}
	if guardBinding == "" {
		b := AccessBinding{Target: target, Policy: guardID, Enabled: true, Order: 0}
		if err := c.managedRequest(ctx, http.MethodPost, "policies/bindings/", b, &b); err != nil {
			return "", err
		}
		guardBinding = b.PK
	}
	if err := c.accessMode(ctx, slug, accessModeAll); err != nil {
		return "", err
	}
	return guardBinding, nil
}
func (c *Client) replaceAccessBindings(ctx context.Context, plan AccessPlan, target, guardID, guardBinding string, bindings []AccessBinding, initiallyManaged bool) error {
	// Once an app is managed, group-only canonical grants belong to the client.
	// Every other binding requires an explicit inventoried replacement ID.
	for _, b := range bindings {
		if b.PK == guardBinding {
			continue
		}
		ownedGroup := (initiallyManaged && b.Policy == "" && b.Group != "" && b.User == 0) || b.Policy == guardID
		if !ownedGroup && !slices.Contains(plan.ReplacesBindings, b.PK) {
			return fmt.Errorf("unapproved existing application binding %s", b.PK)
		}
	}
	// Claim only after the entire original binding inventory was approved, before
	// creating replacement bindings. A restart can then identify partial grants.
	if err := c.managedRequest(ctx, http.MethodPatch, "core/applications/"+url.PathEscape(plan.Slug)+"/", map[string]any{"meta_description": applicationOwner(plan.Owner)}, nil); err != nil {
		return err
	}
	for _, b := range bindings {
		if b.PK == guardBinding {
			continue
		}
		if err := c.managedRequest(ctx, http.MethodDelete, "policies/bindings/"+url.PathEscape(b.PK)+"/", nil, nil); err != nil {
			return err
		}
	}
	for i, g := range plan.Groups {
		b := AccessBinding{Target: target, Group: g.ID, Enabled: true, Order: i + 10}
		if err := c.managedRequest(ctx, http.MethodPost, "policies/bindings/", b, nil); err != nil {
			return err
		}
	}
	// Read back the entire set before opening the application.
	verified, err := c.bindings(ctx, target)
	if err != nil {
		return err
	}
	if !matchingAccess(verified, guardID, plan.Groups) {
		return fmt.Errorf("application binding verification failed")
	}
	return nil
}
