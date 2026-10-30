package controller

import (
	"context"
	"reflect"
	"testing"

	authentikv1alpha1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReconcileDataVolume(t *testing.T) {
	for _, claimName := range []string{"authentik-data", ""} {
		name := claimName
		if name == "" {
			name = "omitted"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, authentikv1alpha1.AddToScheme} {
				if err := add(scheme); err != nil {
					t.Fatal(err)
				}
			}
			server := &authentikv1alpha1.AuthentikServer{
				ObjectMeta: metav1.ObjectMeta{Name: "authentik", Namespace: "test", UID: "server-uid"},
				Spec: authentikv1alpha1.AuthentikServerSpec{
					Host: "auth.example.com", DataVolumeClaimName: claimName,
				},
			}
			objects := []client.Object{server}
			var existingClaim *corev1.PersistentVolumeClaim
			if claimName != "" {
				existingClaim = &corev1.PersistentVolumeClaim{
					ObjectMeta: metav1.ObjectMeta{
						Name:        claimName,
						Namespace:   server.Namespace,
						UID:         "existing-data-uid",
						Labels:      map[string]string{"managed-by": "gitops"},
						Annotations: map[string]string{"helm.sh/resource-policy": "keep"},
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
						StorageClassName: ptr.To("local-path"),
						Resources: corev1.VolumeResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")},
						},
					},
				}
				objects = append(objects, existingClaim)
			}
			r := &AuthentikServerReconciler{
				Client: fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(server).WithObjects(objects...).Build(),
				Scheme: scheme,
			}
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}
			for pass := range 2 {
				if _, err := r.Reconcile(ctx, request); err != nil {
					t.Fatal(err)
				}
				for _, component := range []string{"server", "worker"} {
					deployment := &appsv1.Deployment{}
					if err := r.Get(ctx, types.NamespacedName{Name: server.Name + "-" + component, Namespace: server.Namespace}, deployment); err != nil {
						t.Fatal(err)
					}
					pod := &deployment.Spec.Template.Spec
					assertDataMount(t, pod, component, claimName)
					if claimName != "" && pass == 0 {
						// Exercise correction of existing deployments on the next reconciliation.
						pod.Volumes[0].PersistentVolumeClaim.ClaimName = "wrong-claim"
						pod.Containers[0].VolumeMounts[0].MountPath = "/wrong"
						if err := r.Update(ctx, deployment); err != nil {
							t.Fatal(err)
						}
					}
				}
				assertDataClaimUnchanged(t, ctx, r.Client, server.Namespace, existingClaim)
			}
			current := &authentikv1alpha1.AuthentikServer{}
			if err := r.Get(ctx, request.NamespacedName, current); err != nil {
				t.Fatal(err)
			}
			if claimName != "" {
				current.Spec.DataVolumeClaimName = ""
				if err := r.Update(ctx, current); err != nil {
					t.Fatal(err)
				}
				if _, err := r.Reconcile(ctx, request); err != nil {
					t.Fatal(err)
				}
				for _, component := range []string{"server", "worker"} {
					deployment := &appsv1.Deployment{}
					if err := r.Get(ctx, types.NamespacedName{Name: server.Name + "-" + component, Namespace: server.Namespace}, deployment); err != nil {
						t.Fatal(err)
					}
					pod := &deployment.Spec.Template.Spec
					assertDataMount(t, pod, component, "")
				}
				assertDataClaimUnchanged(t, ctx, r.Client, server.Namespace, existingClaim)
				if err := r.Get(ctx, request.NamespacedName, current); err != nil {
					t.Fatal(err)
				}
				// Deletion with a configured claim must not delete or adopt it either.
				current.Spec.DataVolumeClaimName = claimName
				if err := r.Update(ctx, current); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Delete(ctx, current); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(ctx, request); err != nil {
				t.Fatal(err)
			}
			assertDataClaimUnchanged(t, ctx, r.Client, server.Namespace, existingClaim)
		})
	}
}

func assertDataClaimUnchanged(t *testing.T, ctx context.Context, c client.Client, namespace string, existingClaim *corev1.PersistentVolumeClaim) {
	t.Helper()
	claims := &corev1.PersistentVolumeClaimList{}
	if err := c.List(ctx, claims, client.InNamespace(namespace)); err != nil {
		t.Fatal(err)
	}
	if existingClaim == nil {
		if len(claims.Items) != 0 {
			t.Fatalf("omitted dataVolumeClaimName created claims: %v", claims.Items)
		}
		return
	}
	if len(claims.Items) != 1 {
		t.Fatalf("expected only existing claim, got %d", len(claims.Items))
	}
	claim := &claims.Items[0]
	if claim.UID != existingClaim.UID || claim.Name != existingClaim.Name ||
		!reflect.DeepEqual(claim.Spec, existingClaim.Spec) ||
		!reflect.DeepEqual(claim.Labels, existingClaim.Labels) ||
		!reflect.DeepEqual(claim.Annotations, existingClaim.Annotations) ||
		len(claim.OwnerReferences) != 0 || claim.DeletionTimestamp != nil {
		t.Fatalf("existing claim was replaced, adopted or modified: %+v", claim)
	}
}

func assertDataMount(t *testing.T, pod *corev1.PodSpec, component, claimName string) {
	t.Helper()
	if len(pod.Containers) != 1 {
		t.Fatalf("%s: expected one container", component)
	}
	mounts := pod.Containers[0].VolumeMounts
	if claimName == "" {
		if len(pod.Volumes) != 0 || len(mounts) != 0 {
			t.Fatalf("%s: omitted claim must not add storage", component)
		}
		return
	}
	if len(pod.Volumes) != 1 || pod.Volumes[0].Name != "data" ||
		pod.Volumes[0].PersistentVolumeClaim == nil ||
		pod.Volumes[0].PersistentVolumeClaim.ClaimName != claimName ||
		pod.Volumes[0].PersistentVolumeClaim.ReadOnly {
		t.Fatalf("%s: expected existing writable claim %q, got %+v", component, claimName, pod.Volumes)
	}
	if len(mounts) != 1 || mounts[0].Name != "data" || mounts[0].MountPath != "/data" || mounts[0].ReadOnly || mounts[0].SubPath != "" {
		t.Fatalf("%s: expected writable /data mount, got %+v", component, mounts)
	}
}
