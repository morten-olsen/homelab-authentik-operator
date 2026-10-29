package controller

import (
	"context"
	"fmt"
	"time"

	authv1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
	"github.com/mortenolsen/operator-authentik/internal/authentik"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const groupFinalizer = "authentik.homelab.mortenolsen.pro/group-membership-finalizer"
const accessResync = 30 * time.Second

type AuthentikGroupReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func groupIdentity(g *authv1.AuthentikGroup) authentik.GroupIdentity {
	return authentik.GroupIdentity{ID: g.Status.GroupID, Name: fmt.Sprintf("gitops/%s/%s", g.Namespace, g.Name), Owner: string(g.UID)}
}
func groupMembers(g *authv1.AuthentikGroup) []authentik.UserReference {
	refs := make([]authentik.UserReference, 0, len(g.Spec.Members))
	for _, m := range g.Spec.Members {
		refs = append(refs, authentik.UserReference{ID: m.ID, UUID: m.UUID})
	}
	return refs
}
func serverAPI(ctx context.Context, kube client.Client, ref authv1.NamespacedName) (*authentik.Client, error) {
	var server authv1.AuthentikServer
	if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}, &server); err != nil {
		return nil, fmt.Errorf("referenced server unavailable")
	}
	if !server.Status.Ready {
		return nil, fmt.Errorf("referenced server not ready")
	}
	var secret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Name: server.Status.BootstrapSecretRef, Namespace: server.Namespace}, &secret); err != nil {
		return nil, fmt.Errorf("server bootstrap Secret unavailable")
	}
	if len(secret.Data["token"]) == 0 {
		return nil, fmt.Errorf("server bootstrap token missing")
	}
	return authentik.NewClient(fmt.Sprintf("http://%s.%s.svc.cluster.local:9000", server.Name, server.Namespace), string(secret.Data["token"]), false, ""), nil
}

// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikgroups,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikgroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authentik.homelab.mortenolsen.pro,resources=authentikgroups/finalizers,verbs=update

func (r *AuthentikGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var group authv1.AuthentikGroup
	if err := r.Get(ctx, req.NamespacedName, &group); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if group.DeletionTimestamp.IsZero() && !controllerutil.ContainsFinalizer(&group, groupFinalizer) {
		controllerutil.AddFinalizer(&group, groupFinalizer)
		if err := r.Update(ctx, &group); err != nil {
			return ctrl.Result{}, err
		}
	}
	apiClient, err := serverAPI(ctx, r.Client, group.Spec.ServerRef)
	if err == nil {
		if !group.DeletionTimestamp.IsZero() {
			if controllerutil.ContainsFinalizer(&group, groupFinalizer) {
				if err := apiClient.RevokeGroup(ctx, groupIdentity(&group)); err != nil {
					return ctrl.Result{}, err
				}
				controllerutil.RemoveFinalizer(&group, groupFinalizer)
				return ctrl.Result{}, r.Update(ctx, &group)
			}
			return ctrl.Result{}, nil
		}
		var remote *authentik.ManagedGroup
		remote, err = apiClient.ReconcileGroup(ctx, groupIdentity(&group), groupMembers(&group))
		if remote != nil {
			group.Status.GroupID = remote.PK
		}
	}
	group.Status.Ready = err == nil
	group.Status.ObservedGeneration = group.Generation
	condition := metav1.Condition{Type: "Ready", ObservedGeneration: group.Generation, Status: metav1.ConditionTrue, Reason: "Reconciled", Message: "Group and exact membership reconciled"}
	if err != nil {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "ReconcileFailed"
		condition.Message = err.Error()
	}
	meta.SetStatusCondition(&group.Status.Conditions, condition)
	if updateErr := r.Status().Update(ctx, &group); updateErr != nil {
		return ctrl.Result{}, updateErr
	}
	return ctrl.Result{RequeueAfter: accessResync}, err
}
func (r *AuthentikGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&authv1.AuthentikGroup{}).Named("authentikgroup").Complete(r)
}
