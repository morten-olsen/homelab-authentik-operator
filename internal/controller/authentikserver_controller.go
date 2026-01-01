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

	// Handle finalizers
	stop, err := r.handleFinalizers(ctx, server)
	if stop {
		return ctrl.Result{}, err
	}

	// Set default values
	r.applyDefaults(server)

	// Reconcile components
	if err := r.reconcileComponents(ctx, server); err != nil {
		log.Error(err, "Failed to reconcile components")
		if err := r.Status().Update(ctx, server); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}

	// Check if deployments are ready
	ready, err := r.checkDeploymentStatus(ctx, server)
	if err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, err
	}

	if err := r.Status().Update(ctx, server); err != nil {
		return ctrl.Result{}, err
	}

	if !ready {
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
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
						RunAsUser:    ptr.To(int64(999)),
						RunAsGroup:   ptr.To(int64(999)),
						FSGroup:      ptr.To(int64(999)),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "redis",
							Image: "redis:7-alpine",
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: ptr.To(false),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								RunAsNonRoot: ptr.To(true),
								RunAsUser:    ptr.To(int64(999)),
							},
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

func (r *AuthentikServerReconciler) reconcileAuthentikServerDeployment(ctx context.Context, server *authentikv1alpha1.AuthentikServer, bootstrapSecretName string) error {
	labels := map[string]string{
		"app.kubernetes.io/name":       "authentik",
		"app.kubernetes.io/instance":   server.Name,
		"app.kubernetes.io/component":  "server",
		"app.kubernetes.io/managed-by": "authentik-operator",
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-server", server.Name),
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
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
						RunAsUser:    ptr.To(int64(1000)),
						RunAsGroup:   ptr.To(int64(1000)),
						FSGroup:      ptr.To(int64(1000)),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "authentik",
							Image: server.Spec.Image,
							Args:  []string{"server"},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: ptr.To(false),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								RunAsNonRoot: ptr.To(true),
								RunAsUser:    ptr.To(int64(1000)),
							},
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
							Env: r.getCommonEnv(server, bootstrapSecretName),
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

func (r *AuthentikServerReconciler) reconcileAuthentikWorkerDeployment(ctx context.Context, server *authentikv1alpha1.AuthentikServer, bootstrapSecretName string) error {
	labels := map[string]string{
		"app.kubernetes.io/name":       "authentik",
		"app.kubernetes.io/instance":   server.Name,
		"app.kubernetes.io/component":  "worker",
		"app.kubernetes.io/managed-by": "authentik-operator",
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-worker", server.Name),
			Namespace: server.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		deployment.Labels = labels
		deployment.Spec = appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
						RunAsUser:    ptr.To(int64(1000)),
						RunAsGroup:   ptr.To(int64(1000)),
						FSGroup:      ptr.To(int64(1000)),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "authentik",
							Image: server.Spec.Image,
							Args:  []string{"worker"},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: ptr.To(false),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								RunAsNonRoot: ptr.To(true),
								RunAsUser:    ptr.To(int64(1000)),
							},
							Env: r.getCommonEnv(server, bootstrapSecretName),
						},
					},
				},
			},
		}
		return controllerutil.SetControllerReference(server, deployment, r.Scheme)
	})

	return err
}

func (r *AuthentikServerReconciler) getCommonEnv(server *authentikv1alpha1.AuthentikServer, bootstrapSecretName string) []corev1.EnvVar {
	return []corev1.EnvVar{
		r.getEnvVar("AUTHENTIK_POSTGRESQL__HOST", server.Spec.PostgresHost, server.Spec.PostgresHostSecretRef),
		r.getEnvVar("AUTHENTIK_POSTGRESQL__USER", server.Spec.PostgresUser, server.Spec.PostgresUserSecretRef),
		r.getEnvVar("AUTHENTIK_POSTGRESQL__NAME", server.Spec.PostgresDatabase, server.Spec.PostgresDatabaseSecretRef),
		r.getEnvVar("AUTHENTIK_POSTGRESQL__PASSWORD", server.Spec.PostgresPassword, server.Spec.PostgresPasswordSecretRef),
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
	}
}

func (r *AuthentikServerReconciler) reconcileService(ctx context.Context, server *authentikv1alpha1.AuthentikServer) error {
	labels := map[string]string{
		"app.kubernetes.io/name":       "authentik",
		"app.kubernetes.io/instance":   server.Name,
		"app.kubernetes.io/component":  "server",
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

func (r *AuthentikServerReconciler) getEnvVar(name string, value string, secretRef *authentikv1alpha1.SecretKeyReference) corev1.EnvVar {
	if secretRef != nil {
		return corev1.EnvVar{
			Name: name,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: secretRef.Name,
					},
					Key: secretRef.Key,
				},
			},
		}
	}
	return corev1.EnvVar{
		Name:  name,
		Value: value,
	}
}

func (r *AuthentikServerReconciler) handleFinalizers(ctx context.Context, server *authentikv1alpha1.AuthentikServer) (bool, error) {
	if !server.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(server, authentikServerFinalizer) {
			// Perform cleanup if needed
			controllerutil.RemoveFinalizer(server, authentikServerFinalizer)
			if err := r.Update(ctx, server); err != nil {
				return true, err
			}
		}
		return true, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(server, authentikServerFinalizer) {
		controllerutil.AddFinalizer(server, authentikServerFinalizer)
		if err := r.Update(ctx, server); err != nil {
			return true, err
		}
	}

	return false, nil
}

func (r *AuthentikServerReconciler) reconcileComponents(ctx context.Context, server *authentikv1alpha1.AuthentikServer) error {
	bootstrapSecretName := fmt.Sprintf("%s-bootstrap", server.Name)

	if err := r.reconcileRedis(ctx, server); err != nil {
		r.setCondition(server, "RedisReady", metav1.ConditionFalse, "ReconcileFailed", err.Error())
		return err
	}
	r.setCondition(server, "RedisReady", metav1.ConditionTrue, "Reconciled", "Redis is ready")

	if err := r.reconcileBootstrapSecret(ctx, server, bootstrapSecretName); err != nil {
		r.setCondition(server, "BootstrapSecretReady", metav1.ConditionFalse, "ReconcileFailed", err.Error())
		return err
	}
	r.setCondition(server, "BootstrapSecretReady", metav1.ConditionTrue, "Reconciled", "Bootstrap secret is ready")
	server.Status.BootstrapSecretRef = bootstrapSecretName

	if err := r.reconcileAuthentikServerDeployment(ctx, server, bootstrapSecretName); err != nil {
		r.setCondition(server, "ServerDeploymentReady", metav1.ConditionFalse, "ReconcileFailed", err.Error())
		return err
	}

	if err := r.reconcileAuthentikWorkerDeployment(ctx, server, bootstrapSecretName); err != nil {
		r.setCondition(server, "WorkerDeploymentReady", metav1.ConditionFalse, "ReconcileFailed", err.Error())
		return err
	}

	r.cleanupOldDeployment(ctx, server)

	if err := r.reconcileService(ctx, server); err != nil {
		return err
	}

	return nil
}

func (r *AuthentikServerReconciler) cleanupOldDeployment(ctx context.Context, server *authentikv1alpha1.AuthentikServer) {
	log := logf.FromContext(ctx)
	oldDeployment := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: server.Name, Namespace: server.Namespace}, oldDeployment); err == nil {
		if metav1.IsControlledBy(oldDeployment, server) && oldDeployment.Labels["app.kubernetes.io/component"] == "" {
			log.Info("Deleting old Authentik deployment", "name", oldDeployment.Name)
			if err := r.Delete(ctx, oldDeployment); err != nil {
				log.Error(err, "Failed to delete old Authentik deployment")
			}
		}
	}
}

func (r *AuthentikServerReconciler) checkDeploymentStatus(ctx context.Context, server *authentikv1alpha1.AuthentikServer) (bool, error) {
	serverDeployment := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: fmt.Sprintf("%s-server", server.Name), Namespace: server.Namespace}, serverDeployment); err != nil {
		return false, err
	}

	workerDeployment := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: fmt.Sprintf("%s-worker", server.Name), Namespace: server.Namespace}, workerDeployment); err != nil {
		return false, err
	}

	if serverDeployment.Status.ReadyReplicas > 0 {
		r.setCondition(server, "ServerDeploymentReady", metav1.ConditionTrue, "Reconciled", "Server deployment is ready")
	} else {
		r.setCondition(server, "ServerDeploymentReady", metav1.ConditionFalse, "Pending", "Waiting for server deployment to be ready")
	}

	if workerDeployment.Status.ReadyReplicas > 0 {
		r.setCondition(server, "WorkerDeploymentReady", metav1.ConditionTrue, "Reconciled", "Worker deployment is ready")
	} else {
		r.setCondition(server, "WorkerDeploymentReady", metav1.ConditionFalse, "Pending", "Waiting for worker deployment to be ready")
	}

	server.Status.URL = fmt.Sprintf("https://%s", server.Spec.Host)
	server.Status.Ready = serverDeployment.Status.ReadyReplicas > 0 && workerDeployment.Status.ReadyReplicas > 0

	return server.Status.Ready, nil
}

func (r *AuthentikServerReconciler) applyDefaults(server *authentikv1alpha1.AuthentikServer) {
	if server.Spec.Image == "" {
		server.Spec.Image = "ghcr.io/goauthentik/server:latest"
	}
	if server.Spec.Replicas == nil {
		server.Spec.Replicas = ptr.To(int32(1))
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthentikServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authentikv1alpha1.AuthentikServer{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Named("authentikserver").
		Complete(r)
}
