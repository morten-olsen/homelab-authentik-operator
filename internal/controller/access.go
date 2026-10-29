package controller

import (
	"context"
	"fmt"

	authv1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
	"github.com/mortenolsen/operator-authentik/internal/authentik"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *AuthentikClientReconciler) prepareAccess(ctx context.Context, c *authv1.AuthentikClient, apiClient *authentik.Client) (bool, error) {
	// Legacy clients are preserved only until their first explicit opt-in. A
	// durable Authentik guard also prevents a lost Kubernetes status from reopening
	// an already managed application after an operator restart.
	managed := c.Spec.AllowedGroups != nil || c.Status.AccessManaged || c.Status.ProviderID == 0
	if !managed {
		var err error
		managed, err = apiClient.HasAccessGuard(ctx, string(c.UID))
		if err != nil {
			return false, err
		}
	}
	if !managed {
		r.setCondition(c, "AccessReady", metav1.ConditionUnknown, "LegacyAccessUnmanaged", "Legacy client: application access remains unmanaged until explicit allowedGroups migration")
		return false, nil
	}
	if !c.Status.AccessManaged {
		c.Status.AccessManaged = true
		c.Status.Ready = false
		if err := r.Status().Update(ctx, c); err != nil {
			return true, err
		}
	}
	slug := slugify(fmt.Sprintf("%s-%s", c.Namespace, c.Name))
	plan := authentik.AccessPlan{Slug: slug, Name: c.Spec.Name, Owner: string(c.UID), ProviderID: int32(c.Status.ProviderID), ClaimExisting: c.Status.ApplicationID == slug && c.Status.ProviderID > 0, ReplacesBindings: c.Spec.ReplacesBindings}
	for _, ref := range allowedGroups(c) {
		var group authv1.AuthentikGroup
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}, &group); err != nil {
			plan.ResolutionError = fmt.Errorf("allowed group %s/%s unavailable", ref.Namespace, ref.Name)
			break
		}
		if group.Spec.ServerRef != c.Spec.ServerRef || !group.DeletionTimestamp.IsZero() || !group.Status.Ready || group.Status.ObservedGeneration != group.Generation {
			plan.ResolutionError = fmt.Errorf("allowed group %s/%s is not ready on this server", ref.Namespace, ref.Name)
			break
		}
		id := groupIdentity(&group)
		var err error
		id.Users, err = apiClient.ResolveMembers(ctx, groupMembers(&group))
		if err != nil {
			plan.ResolutionError = err
			break
		}
		plan.Groups = append(plan.Groups, id)
	}
	_, err := apiClient.ReconcileAccess(ctx, plan)
	if err != nil {
		r.setCondition(c, "AccessReady", metav1.ConditionFalse, "ReconcileFailed", err.Error())
		_ = r.Status().Update(ctx, c)
		return true, err
	}
	c.Status.ApplicationID = slug
	r.setCondition(c, "AccessReady", metav1.ConditionTrue, "Reconciled", "Exact allowed groups and ANY bindings verified")
	return true, nil
}
func (r *AuthentikClientReconciler) clientsForGroup(ctx context.Context, obj client.Object) []ctrl.Request {
	var clients authv1.AuthentikClientList
	if err := r.List(ctx, &clients); err != nil {
		return nil
	}
	var requests []ctrl.Request
	for _, c := range clients.Items {
		for _, ref := range allowedGroups(&c) {
			if ref.Name == obj.GetName() && ref.Namespace == obj.GetNamespace() {
				requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&c)})
				break
			}
		}
	}
	return requests
}

func allowedGroups(c *authv1.AuthentikClient) []authv1.NamespacedName {
	if c.Spec.AllowedGroups == nil {
		return nil
	}
	return *c.Spec.AllowedGroups
}
