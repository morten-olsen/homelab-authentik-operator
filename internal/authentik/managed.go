package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"
)

const groupOwnerKey = "authentik.homelab.mortenolsen.pro/owner-uid"

// UserReference pins an existing user across renames and rejects ID reuse.
type UserReference struct {
	ID   int32  `json:"id"`
	UUID string `json:"uuid"`
}
type GroupIdentity struct {
	ID, Name, Owner string
	Users           []int32
}
type ManagedGroup struct {
	PK          string         `json:"pk"`
	Name        string         `json:"name"`
	Users       []int32        `json:"users"`
	IsSuperuser bool           `json:"is_superuser"`
	Parents     []string       `json:"parents"`
	Roles       []string       `json:"roles"`
	Attributes  map[string]any `json:"attributes"`
}

// managedRequest deliberately excludes response bodies from errors: Authentik
// responses can contain identity details and provider credentials. Explicit JSON
// structs also ensure empty membership/role/parent lists are actually sent.
func (c *Client) managedRequest(ctx context.Context, method, path string, body, out any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	cfg := c.api.GetConfig()
	req, err := http.NewRequestWithContext(ctx, method, cfg.Servers[0].URL+"/"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	for k, v := range cfg.DefaultHeader {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	transport := cfg.HTTPClient
	if transport == nil {
		transport = http.DefaultClient
	}
	// Bound each request without mutating the shared SDK transport.
	bounded, cancel := context.WithTimeout(req.Context(), 15*time.Second)
	defer cancel()
	req = req.WithContext(bounded)
	resp, err := transport.Do(req)
	if err != nil {
		return fmt.Errorf("Authentik %s request failed", method)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &managedHTTPError{Status: resp.StatusCode, Method: method}
	}
	if out == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<20))
		return err
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

type managedHTTPError struct {
	Status int
	Method string
}

func (e *managedHTTPError) Error() string {
	return fmt.Sprintf("Authentik %s returned HTTP %d", e.Method, e.Status)
}
func isManagedNotFound(err error) bool {
	e, ok := err.(*managedHTTPError)
	return ok && e.Status == 404
}

func managedList[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	result := []T{}
	separator := "?"
	for _, ch := range path {
		if ch == '?' {
			separator = "&"
			break
		}
	}
	for page := 1; page <= 1000; page++ {
		var data struct {
			Results    *[]T `json:"results"`
			Pagination struct {
				Next *int `json:"next"`
			} `json:"pagination"`
		}
		if err := c.managedRequest(ctx, http.MethodGet, fmt.Sprintf("%s%spage_size=100&page=%d", path, separator, page), nil, &data); err != nil {
			return nil, err
		}
		if data.Results == nil || data.Pagination.Next == nil {
			return nil, fmt.Errorf("malformed paginated Authentik response")
		}
		result = append(result, (*data.Results)...)
		if *data.Pagination.Next == 0 {
			return result, nil
		}
	}
	return nil, fmt.Errorf("Authentik pagination exceeded safety limit")
}

func (c *Client) ResolveMembers(ctx context.Context, refs []UserReference) ([]int32, error) {
	ids := []int32{}
	for _, ref := range refs {
		if ref.ID < 1 || ref.UUID == "" {
			return nil, fmt.Errorf("member id and uuid are required")
		}
		var user struct {
			PK     int32  `json:"pk"`
			UUID   string `json:"uuid"`
			Active bool   `json:"is_active"`
			Type   string `json:"type"`
		}
		if err := c.managedRequest(ctx, http.MethodGet, fmt.Sprintf("core/users/%d/", ref.ID), nil, &user); err != nil {
			return nil, fmt.Errorf("resolve member %d: %w", ref.ID, err)
		}
		if user.PK != ref.ID || user.UUID != ref.UUID || !user.Active || (user.Type != "internal" && user.Type != "external") {
			return nil, fmt.Errorf("member %d must match an active existing human user UUID", ref.ID)
		}
		ids = append(ids, ref.ID)
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

func (c *Client) ReconcileGroup(ctx context.Context, identity GroupIdentity, refs []UserReference) (*ManagedGroup, error) {
	if identity.Name == "" || len(identity.Name) > 150 || identity.Owner == "" {
		return nil, fmt.Errorf("group name and owner are required")
	}
	groups, err := managedList[ManagedGroup](ctx, c, "core/groups/")
	if err != nil {
		return nil, err
	}
	var existing *ManagedGroup
	for i := range groups {
		if groups[i].Name == identity.Name {
			if existing != nil {
				return nil, fmt.Errorf("ambiguous group name")
			}
			existing = &groups[i]
		}
	}
	if existing != nil && existing.Attributes[groupOwnerKey] != identity.Owner {
		return nil, fmt.Errorf("group exists without this resource's ownership marker; refusing adoption")
	}
	ids, memberErr := c.ResolveMembers(ctx, refs)
	if memberErr != nil {
		ids = []int32{}
		if existing == nil {
			return nil, memberErr
		}
	}
	desired := ManagedGroup{Name: identity.Name, Users: ids, Parents: []string{}, Roles: []string{}, Attributes: map[string]any{groupOwnerKey: identity.Owner}}
	path := "core/groups/"
	method := http.MethodPost
	if existing != nil {
		path += url.PathEscape(existing.PK) + "/"
		method = http.MethodPut
	}
	// Do not touch an unmanaged child to repair inheritance. Revoke this group's
	// direct users, report the conflict, and keep referencing applications closed.
	for _, g := range groups {
		if existing != nil && slices.Contains(g.Parents, existing.PK) {
			desired.Users = []int32{}
			memberErr = fmt.Errorf("managed group has an undeclared child group")
		}
	}
	if existing != nil && groupMatches(*existing, desired) {
		if memberErr != nil {
			return existing, memberErr
		}
		return existing, nil
	}
	var group ManagedGroup
	if err := c.managedRequest(ctx, method, path, desired, &group); err != nil {
		return nil, err
	}
	if memberErr != nil {
		return &group, memberErr
	}
	if group.PK == "" || !groupMatches(group, desired) {
		return nil, fmt.Errorf("Authentik did not persist exact group fields")
	}
	return &group, nil
}
func groupMatches(a, b ManagedGroup) bool {
	au := slices.Clone(a.Users)
	slices.Sort(au)
	bu := slices.Clone(b.Users)
	slices.Sort(bu)
	return a.Name == b.Name && slices.Equal(au, bu) && !a.IsSuperuser && len(a.Parents) == 0 && len(a.Roles) == 0 && a.Attributes[groupOwnerKey] == b.Attributes[groupOwnerKey]
}
func (c *Client) ValidateGroup(ctx context.Context, id GroupIdentity) error {
	if id.ID == "" || id.Owner == "" {
		return fmt.Errorf("unresolved group identity")
	}
	var group ManagedGroup
	if err := c.managedRequest(ctx, http.MethodGet, "core/groups/"+url.PathEscape(id.ID)+"/", nil, &group); err != nil {
		return err
	}
	if group.PK != id.ID || !groupMatches(group, ManagedGroup{Name: id.Name, Users: id.Users, Attributes: map[string]any{groupOwnerKey: id.Owner}}) {
		return fmt.Errorf("group ownership, membership or privilege drift")
	}
	groups, err := managedList[ManagedGroup](ctx, c, "core/groups/")
	if err != nil {
		return err
	}
	for _, child := range groups {
		if slices.Contains(child.Parents, id.ID) {
			return fmt.Errorf("managed group has an undeclared child group")
		}
	}
	return nil
}

// RevokeGroup retains the identity object but empties its managed fields. It
// refuses to touch foreign groups, including a CR deleted and recreated by name.
func (c *Client) RevokeGroup(ctx context.Context, id GroupIdentity) error {
	groups, err := managedList[ManagedGroup](ctx, c, "core/groups/")
	if err != nil {
		return err
	}
	var found *ManagedGroup
	for i := range groups {
		if groups[i].Name == id.Name {
			if found != nil {
				return fmt.Errorf("ambiguous group name")
			}
			found = &groups[i]
		}
	}
	if found == nil {
		return nil
	}
	if found.Attributes[groupOwnerKey] != id.Owner {
		return fmt.Errorf("refusing to revoke a foreign group")
	}
	desired := ManagedGroup{Name: id.Name, Users: []int32{}, Parents: []string{}, Roles: []string{}, Attributes: map[string]any{groupOwnerKey: id.Owner}}
	return c.managedRequest(ctx, http.MethodPut, "core/groups/"+url.PathEscape(found.PK)+"/", desired, nil)
}
