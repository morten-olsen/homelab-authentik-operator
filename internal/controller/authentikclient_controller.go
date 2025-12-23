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

package controller

import (
	"context"
	"fmt"
	"regexp"
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
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	api "goauthentik.io/api/v3"

	authentikv1alpha1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
	"github.com/mortenolsen/operator-authentik/internal/authentik"
)

const (
	authentikClientFinalizer = "authentik.homelab.mortenolsen.pro/client-finalizer"
)

// AuthentikClientReconciler reconciles a AuthentikClient object
type AuthentikClientReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikclients/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *AuthentikClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the AuthentikClient instance
	oidcClient := &authentikv1alpha1.AuthentikClient{}
	if err := r.Get(ctx, req.NamespacedName, oidcClient); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(oidcClient, authentikClientFinalizer) {
		controllerutil.AddFinalizer(oidcClient, authentikClientFinalizer)
		if err := r.Update(ctx, oidcClient); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Handle deletion
	if !oidcClient.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, oidcClient)
	}

	// Get the referenced AuthentikServer
	server := &authentikv1alpha1.AuthentikServer{}
	serverKey := types.NamespacedName{
		Name:      oidcClient.Spec.ServerRef.Name,
		Namespace: oidcClient.Spec.ServerRef.Namespace,
	}
	if err := r.Get(ctx, serverKey, server); err != nil {
		log.Error(err, "Failed to get AuthentikServer", "server", serverKey)
		r.setCondition(oidcClient, "ServerReady", metav1.ConditionFalse, "ServerNotFound", err.Error())
		if err := r.Status().Update(ctx, oidcClient); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Check if server is ready
	if !server.Status.Ready {
		log.Info("AuthentikServer is not ready yet", "server", serverKey)
		r.setCondition(oidcClient, "ServerReady", metav1.ConditionFalse, "ServerNotReady", "Waiting for AuthentikServer to be ready")
		if err := r.Status().Update(ctx, oidcClient); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	r.setCondition(oidcClient, "ServerReady", metav1.ConditionTrue, "ServerReady", "AuthentikServer is ready")

	// Get bootstrap secret from server
	bootstrapSecret := &corev1.Secret{}
	bootstrapSecretKey := types.NamespacedName{
		Name:      server.Status.BootstrapSecretRef,
		Namespace: server.Namespace,
	}
	if err := r.Get(ctx, bootstrapSecretKey, bootstrapSecret); err != nil {
		log.Error(err, "Failed to get bootstrap secret", "secret", bootstrapSecretKey)
		r.setCondition(oidcClient, "BootstrapSecretReady", metav1.ConditionFalse, "SecretNotFound", err.Error())
		if err := r.Status().Update(ctx, oidcClient); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	token := string(bootstrapSecret.Data["token"])
	if token == "" {
		err := fmt.Errorf("bootstrap token not found in secret")
		log.Error(err, "Bootstrap token missing", "secret", bootstrapSecretKey)
		r.setCondition(oidcClient, "BootstrapSecretReady", metav1.ConditionFalse, "TokenMissing", err.Error())
		if err := r.Status().Update(ctx, oidcClient); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	r.setCondition(oidcClient, "BootstrapSecretReady", metav1.ConditionTrue, "TokenFound", "Bootstrap token found")

	// Create Authentik API client
	// Use internal service URL for in-cluster communication
	serverURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:9000", server.Name, server.Namespace)
	apiClient := authentik.NewClient(serverURL, token, true, "")

	return r.reconcileNormal(ctx, oidcClient, server, apiClient)
}

func (r *AuthentikClientReconciler) handleDeletion(ctx context.Context, oidcClient *authentikv1alpha1.AuthentikClient) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(oidcClient, authentikClientFinalizer) {
		// Get the referenced AuthentikServer to get the API token
		server := &authentikv1alpha1.AuthentikServer{}
		serverKey := types.NamespacedName{
			Name:      oidcClient.Spec.ServerRef.Name,
			Namespace: oidcClient.Spec.ServerRef.Namespace,
		}
		if err := r.Get(ctx, serverKey, server); err == nil && server.Status.Ready {
			bootstrapSecret := &corev1.Secret{}
			bootstrapSecretKey := types.NamespacedName{
				Name:      server.Status.BootstrapSecretRef,
				Namespace: server.Namespace,
			}
			if err := r.Get(ctx, bootstrapSecretKey, bootstrapSecret); err == nil {
				token := string(bootstrapSecret.Data["token"])
				if token != "" {
					serverURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:9000", server.Name, server.Namespace)
					apiClient := authentik.NewClient(serverURL, token, true, "")
					// Delete resources from Authentik
					r.cleanupAuthentikResources(ctx, oidcClient, apiClient)
				}
			}
		}

		controllerutil.RemoveFinalizer(oidcClient, authentikClientFinalizer)
		if err := r.Update(ctx, oidcClient); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *AuthentikClientReconciler) reconcileNormal(ctx context.Context, oidcClient *authentikv1alpha1.AuthentikClient, server *authentikv1alpha1.AuthentikServer, apiClient *authentik.Client) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	// Set default values
	if oidcClient.Spec.ClientType == "" {
		oidcClient.Spec.ClientType = "confidential"
	}
	if len(oidcClient.Spec.Scopes) == 0 {
		oidcClient.Spec.Scopes = []string{"openid", "profile", "email"}
	}

	// Get the authorization flow
	authFlow, err := apiClient.GetAuthorizationFlow(ctx)
	if err != nil {
		log.Error(err, "Failed to get authorization flow")
		r.setCondition(oidcClient, "ProviderReady", metav1.ConditionFalse, "FlowNotFound", err.Error())
		if err := r.Status().Update(ctx, oidcClient); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Get the invalidation flow
	invalidationFlow, err := apiClient.GetInvalidationFlow(ctx)
	if err != nil {
		log.Error(err, "Failed to get invalidation flow")
		r.setCondition(oidcClient, "ProviderReady", metav1.ConditionFalse, "FlowNotFound", err.Error())
		if err := r.Status().Update(ctx, oidcClient); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Get scope mappings
	scopeMappings, err := apiClient.GetScopeMappings(ctx, oidcClient.Spec.Scopes)
	if err != nil {
		log.Error(err, "Failed to get scope mappings")
		// Continue without scope mappings
		scopeMappings = []string{}
	}

	// Create or update OAuth2 provider
	providerName := fmt.Sprintf("%s-%s", oidcClient.Namespace, oidcClient.Name)
	provider, err := apiClient.GetOAuth2ProviderByName(ctx, providerName)
	if err != nil {
		log.Error(err, "Failed to check for existing provider")
		r.setCondition(oidcClient, "ProviderReady", metav1.ConditionFalse, "APIError", err.Error())
		if err := r.Status().Update(ctx, oidcClient); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	if provider == nil {
		// Create new provider
		provider, err = apiClient.CreateOAuth2Provider(ctx, providerName, authFlow.GetPk(), invalidationFlow.GetPk(), oidcClient.Spec.RedirectURIs, oidcClient.Spec.ClientType, scopeMappings)
		if err != nil {
			log.Error(err, "Failed to create OAuth2 provider")
			r.setCondition(oidcClient, "ProviderReady", metav1.ConditionFalse, "CreateFailed", err.Error())
			if err := r.Status().Update(ctx, oidcClient); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
		log.Info("Created OAuth2 provider", "name", providerName, "pk", provider.GetPk())
	} else {
		// Update existing provider
		provider, err = apiClient.UpdateOAuth2Provider(ctx, provider.GetPk(), providerName, authFlow.GetPk(), invalidationFlow.GetPk(), oidcClient.Spec.RedirectURIs, oidcClient.Spec.ClientType, scopeMappings)
		if err != nil {
			log.Error(err, "Failed to update OAuth2 provider")
			r.setCondition(oidcClient, "ProviderReady", metav1.ConditionFalse, "UpdateFailed", err.Error())
			if err := r.Status().Update(ctx, oidcClient); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
		log.Info("Updated OAuth2 provider", "name", providerName, "pk", provider.GetPk())
	}

	oidcClient.Status.ProviderID = int(provider.GetPk())
	oidcClient.Status.ClientID = provider.GetClientId()
	r.setCondition(oidcClient, "ProviderReady", metav1.ConditionTrue, "Reconciled", "OAuth2 provider is ready")

	// Create or update Application
	appSlug := slugify(providerName)
	if err := r.reconcileApplication(ctx, oidcClient, appSlug, provider, apiClient); err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}

	oidcClient.Status.ApplicationID = appSlug
	r.setCondition(oidcClient, "ApplicationReady", metav1.ConditionTrue, "Reconciled", "Application is ready")

	// Create OIDC credentials secret
	secretName := oidcClient.Spec.SecretName
	if secretName == "" {
		secretName = fmt.Sprintf("%s-oidc-credentials", oidcClient.Name)
	}

	if err := r.reconcileCredentialsSecret(ctx, oidcClient, secretName, server, provider); err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}

	oidcClient.Status.SecretName = secretName
	r.setCondition(oidcClient, "SecretReady", metav1.ConditionTrue, "Reconciled", "Credentials secret is ready")

	// Update final status
	oidcClient.Status.Ready = true
	if err := r.Status().Update(ctx, oidcClient); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled AuthentikClient",
		"name", oidcClient.Name,
		"clientId", oidcClient.Status.ClientID,
		"secretName", oidcClient.Status.SecretName)

	return ctrl.Result{}, nil
}

func (r *AuthentikClientReconciler) reconcileApplication(ctx context.Context, oidcClient *authentikv1alpha1.AuthentikClient, appSlug string, provider *api.OAuth2Provider, apiClient *authentik.Client) error {
	log := logf.FromContext(ctx)
	app, err := apiClient.GetApplicationBySlug(ctx, appSlug)
	if err != nil {
		log.Error(err, "Failed to check for existing application")
		r.setCondition(oidcClient, "ApplicationReady", metav1.ConditionFalse, "APIError", err.Error())
		_ = r.Status().Update(ctx, oidcClient)
		return err
	}

	if app == nil {
		// Create new application
		_, err = apiClient.CreateApplication(ctx, appSlug, oidcClient.Spec.Name, provider.GetPk())
		if err != nil {
			log.Error(err, "Failed to create application")
			r.setCondition(oidcClient, "ApplicationReady", metav1.ConditionFalse, "CreateFailed", err.Error())
			_ = r.Status().Update(ctx, oidcClient)
			return err
		}
		log.Info("Created application", "slug", appSlug)
	} else {
		// Update existing application
		_, err = apiClient.UpdateApplication(ctx, appSlug, oidcClient.Spec.Name, provider.GetPk())
		if err != nil {
			log.Error(err, "Failed to update application")
			r.setCondition(oidcClient, "ApplicationReady", metav1.ConditionFalse, "UpdateFailed", err.Error())
			_ = r.Status().Update(ctx, oidcClient)
			return err
		}
		log.Info("Updated application", "slug", appSlug)
	}
	return nil
}

func (r *AuthentikClientReconciler) reconcileCredentialsSecret(ctx context.Context, oidcClient *authentikv1alpha1.AuthentikClient, secretName string, server *authentikv1alpha1.AuthentikServer, provider *api.OAuth2Provider) error {
	log := logf.FromContext(ctx)
	// Build OIDC URLs
	baseURL := server.Status.URL
	appSlug := slugify(fmt.Sprintf("%s-%s", oidcClient.Namespace, oidcClient.Name))
	issuer := fmt.Sprintf("%s/application/o/%s/", baseURL, appSlug)
	authorizationURL := fmt.Sprintf("%s/application/o/authorize/", baseURL)
	tokenURL := fmt.Sprintf("%s/application/o/token/", baseURL)
	userinfoURL := fmt.Sprintf("%s/application/o/userinfo/", baseURL)
	jwksURL := fmt.Sprintf("%s/application/o/%s/jwks/", baseURL, appSlug)

	credentialsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: oidcClient.Namespace,
		},
	}

	clientSecret := ""
	if provider.ClientSecret != nil {
		clientSecret = *provider.ClientSecret
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, credentialsSecret, func() error {
		credentialsSecret.Type = corev1.SecretTypeOpaque
		credentialsSecret.StringData = map[string]string{
			"clientId":         provider.GetClientId(),
			"clientSecret":     clientSecret,
			"issuer":           issuer,
			"authorizationUrl": authorizationURL,
			"tokenUrl":         tokenURL,
			"userinfoUrl":      userinfoURL,
			"jwksUrl":          jwksURL,
		}
		return controllerutil.SetControllerReference(oidcClient, credentialsSecret, r.Scheme)
	})
	if err != nil {
		log.Error(err, "Failed to create/update credentials secret")
		r.setCondition(oidcClient, "SecretReady", metav1.ConditionFalse, "CreateFailed", err.Error())
		_ = r.Status().Update(ctx, oidcClient)
		return err
	}
	return nil
}

func (r *AuthentikClientReconciler) cleanupAuthentikResources(ctx context.Context, oidcClient *authentikv1alpha1.AuthentikClient, apiClient *authentik.Client) {
	log := logf.FromContext(ctx)

	// Delete application first
	appSlug := slugify(fmt.Sprintf("%s-%s", oidcClient.Namespace, oidcClient.Name))
	if err := apiClient.DeleteApplication(ctx, appSlug); err != nil {
		log.Error(err, "Failed to delete application", "slug", appSlug)
		// Continue to try deleting provider
	}

	// Delete provider
	if oidcClient.Status.ProviderID > 0 {
		if err := apiClient.DeleteOAuth2Provider(ctx, int32(oidcClient.Status.ProviderID)); err != nil {
			log.Error(err, "Failed to delete provider", "id", oidcClient.Status.ProviderID)
		}
	}
}

func (r *AuthentikClientReconciler) setCondition(oidcClient *authentikv1alpha1.AuthentikClient, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&oidcClient.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

func slugify(s string) string {
	// Convert to lowercase
	s = strings.ToLower(s)
	// Replace non-alphanumeric characters with hyphens
	reg := regexp.MustCompile(`[^a-z0-9]+`)
	s = reg.ReplaceAllString(s, "-")
	// Remove leading/trailing hyphens
	s = strings.Trim(s, "-")
	return s
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthentikClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authentikv1alpha1.AuthentikClient{}).
		Owns(&corev1.Secret{}).
		Named("authentikclient").
		Complete(r)
}
