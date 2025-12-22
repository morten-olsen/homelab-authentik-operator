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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	authentikv1alpha1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
)

const (
	authentikServerFinalizer = "authentik.homelab.mortenolsen.pro/finalizer"
)

// AuthentikServerReconciler reconciles a AuthentikServer object
type AuthentikServerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikservers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikservers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikservers/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete

func (r *AuthentikServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the AuthentikServer instance
	server := &authentikv1alpha1.AuthentikServer{}
	if err := r.Get(ctx, req.NamespacedName, server); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !server.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(server, authentikServerFinalizer) {
			// Perform cleanup if needed
			controllerutil.RemoveFinalizer(server, authentikServerFinalizer)
			if err := r.Update(ctx, server); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(server, authentikServerFinalizer) {
		controllerutil.AddFinalizer(server, authentikServerFinalizer)
		if err := r.Update(ctx, server); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Set default values
	if server.Spec.Image == "" {
		server.Spec.Image = "ghcr.io/goauthentik/server:latest"
	}
	if server.Spec.Replicas == nil {
		server.Spec.Replicas = ptr.To(int32(1))
	}

	// Create or update Redis
	if err := r.reconcileRedis(ctx, server); err != nil {
		log.Error(err, "Failed to reconcile Redis")
		r.setCondition(server, "RedisReady", metav1.ConditionFalse, "ReconcileFailed", err.Error())
		if err := r.Status().Update(ctx, server); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}
	r.setCondition(server, "RedisReady", metav1.ConditionTrue, "Reconciled", "Redis is ready")

	// Create bootstrap secret if not exists
	bootstrapSecretName := fmt.Sprintf("%s-bootstrap", server.Name)
	if err := r.reconcileBootstrapSecret(ctx, server, bootstrapSecretName); err != nil {
		log.Error(err, "Failed to reconcile bootstrap secret")
		r.setCondition(server, "BootstrapSecretReady", metav1.ConditionFalse, "ReconcileFailed", err.Error())
		if err := r.Status().Update(ctx, server); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}
	r.setCondition(server, "BootstrapSecretReady", metav1.ConditionTrue, "Reconciled", "Bootstrap secret is ready")
	server.Status.BootstrapSecretRef = bootstrapSecretName

	// Create or update Authentik deployment
	if err := r.reconcileAuthentikDeployment(ctx, server, bootstrapSecretName); err != nil {
		log.Error(err, "Failed to reconcile Authentik deployment")
		r.setCondition(server, "DeploymentReady", metav1.ConditionFalse, "ReconcileFailed", err.Error())
		if err := r.Status().Update(ctx, server); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}

	// Check if deployment is ready
	deployment := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: server.Name, Namespace: server.Namespace}, deployment); err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}

	if deployment.Status.ReadyReplicas > 0 {
		r.setCondition(server, "DeploymentReady", metav1.ConditionTrue, "Reconciled", "Deployment is ready")
	} else {
		r.setCondition(server, "DeploymentReady", metav1.ConditionFalse, "Pending", "Waiting for deployment to be ready")
	}

	// Create or update Service
	if err := r.reconcileService(ctx, server); err != nil {
		log.Error(err, "Failed to reconcile Service")
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}

	// Create or update Ingress
	if err := r.reconcileIngress(ctx, server); err != nil {
		log.Error(err, "Failed to reconcile Ingress")
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}

	// Update status
	scheme := "http"
	if server.Spec.TLS != nil && server.Spec.TLS.Enabled {
		scheme = "https"
	}
	server.Status.URL = fmt.Sprintf("%s://%s", scheme, server.Spec.Host)
	server.Status.Ready = deployment.Status.ReadyReplicas > 0

	if err := r.Status().Update(ctx, server); err != nil {
		return ctrl.Result{}, err
	}

	if !server.Status.Ready {
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}

func (r *AuthentikServerReconciler) reconcileRedis(ctx context.Context, server *authentikv1alpha1.AuthentikServer) error {
	labels := map[string]string{
		"app.kubernetes.io/name":       "redis",
		"app.kubernetes.io/instance":   server.Name,
		"app.kubernetes.io/managed-by": "authentik-operator",
	}

	// Redis Deployment
	redisDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-redis", server.Name),
			Namespace: server.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, redisDeployment, func() error {
		redisDeployment.Labels = labels
		redisDeployment.Spec = appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "redis",
							Image: "redis:7-alpine",
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 6379,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							Resources: corev1.ResourceRequirements{},
						},
					},
				},
			},
		}
		return controllerutil.SetControllerReference(server, redisDeployment, r.Scheme)
	})
	if err != nil {
		return err
	}

	// Redis Service
	redisService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-redis", server.Name),
			Namespace: server.Namespace,
		},
	}

	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, redisService, func() error {
		redisService.Labels = labels
		redisService.Spec = corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{
				{
					Port:       6379,
					TargetPort: intstr.FromInt(6379),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		}
		return controllerutil.SetControllerReference(server, redisService, r.Scheme)
	})

	return err
}

func (r *AuthentikServerReconciler) reconcileBootstrapSecret(ctx context.Context, server *authentikv1alpha1.AuthentikServer, secretName string) error {
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: server.Namespace}, secret)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	// If secret exists, don't regenerate
	if err == nil {
		return nil
	}

	// Generate random values
	token, err := generateRandomString(32)
	if err != nil {
		return err
	}
	password, err := generateRandomString(24)
	if err != nil {
		return err
	}
	secretKey, err := generateRandomString(50)
	if err != nil {
		return err
	}

	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: server.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"token":      token,
			"password":   password,
			"secret-key": secretKey,
			"email":      fmt.Sprintf("admin@%s", server.Spec.Host),
		},
	}

	if err := controllerutil.SetControllerReference(server, secret, r.Scheme); err != nil {
		return err
	}

	return r.Create(ctx, secret)
}

func (r *AuthentikServerReconciler) reconcileAuthentikDeployment(ctx context.Context, server *authentikv1alpha1.AuthentikServer, bootstrapSecretName string) error {
	labels := map[string]string{
		"app.kubernetes.io/name":       "authentik",
		"app.kubernetes.io/instance":   server.Name,
		"app.kubernetes.io/managed-by": "authentik-operator",
	}

	// Get postgres secret namespace
	postgresSecretNamespace := server.Spec.PostgresSecretRef.Namespace
	if postgresSecretNamespace == "" {
		postgresSecretNamespace = server.Namespace
	}

	// Get the postgres secret key
	postgresSecretKey := server.Spec.PostgresSecretRef.Key
	if postgresSecretKey == "" {
		postgresSecretKey = "url"
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      server.Name,
			Namespace: server.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		deployment.Labels = labels
		deployment.Spec = appsv1.DeploymentSpec{
			Replicas: server.Spec.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "authentik",
							Image: server.Spec.Image,
							Args:  []string{"server"},
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: 9000,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "https",
									ContainerPort: 9443,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							Env: []corev1.EnvVar{
								{
									Name: "AUTHENTIK_POSTGRESQL__HOST",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: server.Spec.PostgresSecretRef.Name,
											},
											Key: postgresSecretKey,
										},
									},
								},
								{
									Name:  "AUTHENTIK_REDIS__HOST",
									Value: fmt.Sprintf("%s-redis", server.Name),
								},
								{
									Name: "AUTHENTIK_SECRET_KEY",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: bootstrapSecretName,
											},
											Key: "secret-key",
										},
									},
								},
								{
									Name: "AUTHENTIK_BOOTSTRAP_TOKEN",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: bootstrapSecretName,
											},
											Key: "token",
										},
									},
								},
								{
									Name: "AUTHENTIK_BOOTSTRAP_PASSWORD",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: bootstrapSecretName,
											},
											Key: "password",
										},
									},
								},
								{
									Name: "AUTHENTIK_BOOTSTRAP_EMAIL",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: bootstrapSecretName,
											},
											Key: "email",
										},
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/-/health/live/",
										Port: intstr.FromInt(9000),
									},
								},
								InitialDelaySeconds: 50,
								PeriodSeconds:       10,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/-/health/ready/",
										Port: intstr.FromInt(9000),
									},
								},
								InitialDelaySeconds: 50,
								PeriodSeconds:       10,
							},
						},
					},
				},
			},
		}
		return controllerutil.SetControllerReference(server, deployment, r.Scheme)
	})

	return err
}

func (r *AuthentikServerReconciler) reconcileService(ctx context.Context, server *authentikv1alpha1.AuthentikServer) error {
	labels := map[string]string{
		"app.kubernetes.io/name":       "authentik",
		"app.kubernetes.io/instance":   server.Name,
		"app.kubernetes.io/managed-by": "authentik-operator",
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      server.Name,
			Namespace: server.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, service, func() error {
		service.Labels = labels
		service.Spec = corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       9000,
					TargetPort: intstr.FromInt(9000),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "https",
					Port:       9443,
					TargetPort: intstr.FromInt(9443),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		}
		return controllerutil.SetControllerReference(server, service, r.Scheme)
	})

	return err
}

func (r *AuthentikServerReconciler) reconcileIngress(ctx context.Context, server *authentikv1alpha1.AuthentikServer) error {
	labels := map[string]string{
		"app.kubernetes.io/name":       "authentik",
		"app.kubernetes.io/instance":   server.Name,
		"app.kubernetes.io/managed-by": "authentik-operator",
	}

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      server.Name,
			Namespace: server.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, ingress, func() error {
		ingress.Labels = labels
		pathType := networkingv1.PathTypePrefix

		ingress.Spec = networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: server.Spec.Host,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: server.Name,
											Port: networkingv1.ServiceBackendPort{
												Number: 9000,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		if server.Spec.TLS != nil && server.Spec.TLS.Enabled {
			ingress.Spec.TLS = []networkingv1.IngressTLS{
				{
					Hosts:      []string{server.Spec.Host},
					SecretName: server.Spec.TLS.SecretName,
				},
			}
		}

		return controllerutil.SetControllerReference(server, ingress, r.Scheme)
	})

	return err
}

func (r *AuthentikServerReconciler) setCondition(server *authentikv1alpha1.AuthentikServer, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&server.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthentikServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authentikv1alpha1.AuthentikServer{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(&networkingv1.Ingress{}).
		Named("authentikserver").
		Complete(r)
}
