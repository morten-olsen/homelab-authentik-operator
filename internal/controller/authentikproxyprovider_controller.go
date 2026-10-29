package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	authv1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
	"github.com/mortenolsen/operator-authentik/internal/authentik"
)

const authentikProxyProviderFinalizer = "authentik.homelab.mortenolsen.pro/proxy-provider-finalizer"

// providerIDAnnotation records the created provider's ID on the object itself,
// so a lost status still identifies the one provider this resource may modify.
const providerIDAnnotation = "authentik.homelab.mortenolsen.pro/provider-id"

// AuthentikProxyProviderReconciler reconciles a forward-auth proxy provider, its
// application access and its attachment to the server's embedded outpost.
type AuthentikProxyProviderReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// NewAPIClient builds the Authentik client; tests replace it.
	NewAPIClient func(server *authv1.AuthentikServer, token string) *authentik.Client
}

// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikproxyproviders,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikproxyproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikproxyproviders/finalizers,verbs=update

func (r *AuthentikProxyProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	p := &authv1.AuthentikProxyProvider{}
	if err := r.Get(ctx, req.NamespacedName, p); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !p.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, p)
	}
	if !controllerutil.ContainsFinalizer(p, authentikProxyProviderFinalizer) {
		controllerutil.AddFinalizer(p, authentikProxyProviderFinalizer)
		if err := r.Update(ctx, p); err != nil {
			return ctrl.Result{}, err
		}
	}

	server, apiClient, err := r.connect(ctx, p)
	if err != nil {
		r.setCondition(p, "ServerReady", metav1.ConditionFalse, "Unavailable", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, r.Status().Update(ctx, p)
	}
	r.setCondition(p, "ServerReady", metav1.ConditionTrue, "ServerReady", "AuthentikServer is ready")
	return r.reconcileNormal(ctx, p, server, apiClient)
}

// connect resolves the referenced server and its bootstrap token. Errors carry
// no secret material.
func (r *AuthentikProxyProviderReconciler) connect(ctx context.Context, p *authv1.AuthentikProxyProvider) (*authv1.AuthentikServer, *authentik.Client, error) {
	server := &authv1.AuthentikServer{}
	if err := r.Get(ctx, types.NamespacedName{Name: p.Spec.ServerRef.Name, Namespace: p.Spec.ServerRef.Namespace}, server); err != nil {
		return nil, nil, err
	}
	if !server.Status.Ready {
		return server, nil, fmt.Errorf("AuthentikServer %s/%s is not ready", server.Namespace, server.Name)
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: server.Status.BootstrapSecretRef, Namespace: server.Namespace}, secret); err != nil {
		return server, nil, fmt.Errorf("bootstrap secret unavailable: %w", err)
	}
	token := string(secret.Data["token"])
	if token == "" {
		return server, nil, fmt.Errorf("bootstrap token not found in secret")
	}
	newClient := r.NewAPIClient
	if newClient == nil {
		newClient = defaultAPIClient
	}
	return server, newClient(server, token), nil
}

func defaultAPIClient(server *authv1.AuthentikServer, token string) *authentik.Client {
	return authentik.NewClient(fmt.Sprintf("http://%s.%s.svc.cluster.local:9000", server.Name, server.Namespace), token, true, "")
}

// knownProviderID prefers status and falls back to the annotation.
func knownProviderID(p *authv1.AuthentikProxyProvider) int32 {
	if p.Status.ProviderID > 0 {
		return int32(p.Status.ProviderID)
	}
	id, err := strconv.ParseInt(p.Annotations[providerIDAnnotation], 10, 32)
	if err != nil || id <= 0 {
		return 0
	}
	return int32(id)
}

// hostConflict reports an older resource on the same server claiming the same
// external host; the outpost selects providers by host, so only one may own it.
func (r *AuthentikProxyProviderReconciler) hostConflict(ctx context.Context, p *authv1.AuthentikProxyProvider) (string, error) {
	var list authv1.AuthentikProxyProviderList
	if err := r.List(ctx, &list); err != nil {
		return "", err
	}
	for _, other := range list.Items {
		if other.UID == p.UID || other.Spec.ServerRef != p.Spec.ServerRef || !strings.EqualFold(other.Spec.ExternalHost, p.Spec.ExternalHost) {
			continue
		}
		older := other.CreationTimestamp.Before(&p.CreationTimestamp) ||
			(other.CreationTimestamp.Equal(&p.CreationTimestamp) && other.Namespace+"/"+other.Name < p.Namespace+"/"+p.Name)
		if older {
			return other.Namespace + "/" + other.Name, nil
		}
	}
	return "", nil
}

func proxySlug(p *authv1.AuthentikProxyProvider) string {
	return slugify(fmt.Sprintf("%s-%s", p.Namespace, p.Name))
}

// reconcileNormal follows the AuthentikClient ordering from ADR 0001: access is
// verified on a disconnected application first, the provider identity is
// persisted next, and only then is the provider attached to the application and
// the outpost. Any access failure leaves the application disconnected.
func (r *AuthentikProxyProviderReconciler) reconcileNormal(ctx context.Context, p *authv1.AuthentikProxyProvider, server *authv1.AuthentikServer, apiClient *authentik.Client) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	slug := proxySlug(p)
	fail := func(condition, reason string, err error) (ctrl.Result, error) {
		r.setCondition(p, condition, metav1.ConditionFalse, reason, err.Error())
		if statusErr := r.Status().Update(ctx, p); statusErr != nil {
			log.Error(statusErr, "Failed to record status")
		}
		return ctrl.Result{RequeueAfter: accessResync}, err
	}

	if owner, err := r.hostConflict(ctx, p); err != nil {
		return ctrl.Result{}, err
	} else if owner != "" {
		return fail("ProviderReady", "HostConflict", fmt.Errorf("externalHost is already claimed by %s", owner))
	}

	knownID := knownProviderID(p)
	plan := authentik.AccessPlan{Slug: slug, Name: p.Spec.Name, Owner: string(p.UID), ProviderID: knownID, ClaimExisting: p.Status.ApplicationID == slug && knownID > 0}
	plan.Groups, plan.ResolutionError = resolveAllowedGroups(ctx, r.Client, apiClient, p.Spec.ServerRef, p.Spec.AllowedGroups)
	if _, err := apiClient.ReconcileAccess(ctx, plan); err != nil {
		return fail("AccessReady", "ReconcileFailed", err)
	}
	p.Status.ApplicationID = slug
	r.setCondition(p, "AccessReady", metav1.ConditionTrue, "Reconciled", "Exact allowed groups and ANY bindings verified")

	authFlow, err := apiClient.GetAuthorizationFlow(ctx)
	if err != nil {
		return fail("ProviderReady", "FlowNotFound", err)
	}
	invalidationFlow, err := apiClient.GetInvalidationFlow(ctx)
	if err != nil {
		return fail("ProviderReady", "FlowNotFound", err)
	}
	mode := p.Spec.Mode
	if mode == "" {
		mode = "forward_single"
	}
	validity := p.Spec.AccessTokenValidity
	if validity == "" {
		validity = "hours=8"
	}
	provider, err := apiClient.ReconcileProxyProvider(ctx, authentik.ProxyPlan{
		Desired: authentik.ProxyProvider{
			Name:                fmt.Sprintf("%s-%s", p.Namespace, p.Name),
			AuthorizationFlow:   authFlow.GetPk(),
			InvalidationFlow:    invalidationFlow.GetPk(),
			ExternalHost:        p.Spec.ExternalHost,
			Mode:                mode,
			AccessTokenValidity: validity,
		},
		KnownID: knownID,
		AppSlug: slug,
	})
	if err != nil {
		return fail("ProviderReady", "ReconcileFailed", err)
	}
	if want := strconv.Itoa(int(provider.PK)); p.Annotations[providerIDAnnotation] != want {
		// Record ownership on the object before attaching the provider anywhere.
		// Update returns the stored object, so status edits come after it.
		if p.Annotations == nil {
			p.Annotations = map[string]string{}
		}
		p.Annotations[providerIDAnnotation] = want
		if err := r.Update(ctx, p); err != nil {
			return ctrl.Result{}, err
		}
		p.Status.ApplicationID = slug
		r.setCondition(p, "AccessReady", metav1.ConditionTrue, "Reconciled", "Exact allowed groups and ANY bindings verified")
	}
	r.setCondition(p, "ProviderReady", metav1.ConditionTrue, "Reconciled", "Proxy provider is ready")
	if p.Status.ProviderID != int(provider.PK) {
		// Persist the provider identity before attaching it anywhere.
		p.Status.ProviderID = int(provider.PK)
		p.Status.Ready = false
		if err := r.Status().Update(ctx, p); err != nil {
			return ctrl.Result{}, err
		}
	}

	if err := apiClient.ConnectApplication(ctx, slug, p.Spec.Name, provider.PK); err != nil {
		return fail("ApplicationReady", "ConnectFailed", err)
	}
	r.setCondition(p, "ApplicationReady", metav1.ConditionTrue, "Reconciled", "Application is connected")

	outpostID, err := apiClient.AttachToEmbeddedOutpost(ctx, provider.PK, "https://"+server.Spec.Host)
	if err != nil {
		return fail("OutpostReady", "AttachFailed", err)
	}
	p.Status.OutpostID = outpostID
	r.setCondition(p, "OutpostReady", metav1.ConditionTrue, "Reconciled", "Provider is served by the embedded outpost")

	p.Status.Ready = true
	p.Status.ObservedGeneration = p.Generation
	if err := r.Status().Update(ctx, p); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: accessResync}, nil
}

// handleDeletion detaches the provider from the outpost, then removes the owned
// application and the provider. The finalizer is kept while Authentik cannot be
// reached, unless the referenced server itself no longer exists.
func (r *AuthentikProxyProviderReconciler) handleDeletion(ctx context.Context, p *authv1.AuthentikProxyProvider) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(p, authentikProxyProviderFinalizer) {
		return ctrl.Result{}, nil
	}
	err := r.Get(ctx, types.NamespacedName{Name: p.Spec.ServerRef.Name, Namespace: p.Spec.ServerRef.Namespace}, &authv1.AuthentikServer{})
	switch {
	case apierrors.IsNotFound(err):
		logf.FromContext(ctx).Info("AuthentikServer is gone; releasing proxy provider without Authentik cleanup")
	case err != nil:
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	default:
		_, apiClient, err := r.connect(ctx, p)
		if err != nil {
			return ctrl.Result{RequeueAfter: 30 * time.Second}, err
		}
		if err := r.cleanup(ctx, p, apiClient); err != nil {
			return ctrl.Result{RequeueAfter: 30 * time.Second}, err
		}
	}
	controllerutil.RemoveFinalizer(p, authentikProxyProviderFinalizer)
	return ctrl.Result{}, r.Update(ctx, p)
}

func (r *AuthentikProxyProviderReconciler) cleanup(ctx context.Context, p *authv1.AuthentikProxyProvider, apiClient *authentik.Client) error {
	id := knownProviderID(p)
	if id > 0 {
		if err := apiClient.DetachFromEmbeddedOutpost(ctx, id); err != nil {
			return err
		}
	}
	if err := apiClient.DeleteOwnedApplication(ctx, proxySlug(p), string(p.UID)); err != nil {
		return err
	}
	if id > 0 {
		return apiClient.DeleteProxyProvider(ctx, id)
	}
	return nil
}

func (r *AuthentikProxyProviderReconciler) setCondition(p *authv1.AuthentikProxyProvider, conditionType string, status metav1.ConditionStatus, reason, message string) {
	if status == metav1.ConditionFalse {
		p.Status.Ready = false
	}
	meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
		ObservedGeneration: p.Generation,
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

func (r *AuthentikProxyProviderReconciler) providersForGroup(ctx context.Context, obj client.Object) []ctrl.Request {
	var list authv1.AuthentikProxyProviderList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var requests []ctrl.Request
	for _, p := range list.Items {
		for _, ref := range p.Spec.AllowedGroups {
			if ref.Name == obj.GetName() && ref.Namespace == obj.GetNamespace() {
				requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&p)})
				break
			}
		}
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthentikProxyProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authv1.AuthentikProxyProvider{}).
		Watches(&authv1.AuthentikGroup{}, handler.EnqueueRequestsFromMapFunc(r.providersForGroup)).
		Named("authentikproxyprovider").
		Complete(r)
}
