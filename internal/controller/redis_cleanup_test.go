package controller

import (
	"context"
	"reflect"
	"testing"

	authentikv1alpha1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReconcileRetiresObsoleteRedis(t *testing.T) {
	for _, tc := range []struct {
		name       string
		exists     bool
		ownerUID   types.UID
		controller bool
		removed    bool
	}{
		{name: "absent"},
		{name: "owned", exists: true, ownerUID: "server-uid", controller: true, removed: true},
		{name: "foreign controller", exists: true, ownerUID: "previous-server-uid", controller: true},
		{name: "unowned", exists: true},
		{name: "non-controller owner", exists: true, ownerUID: "server-uid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
					Image:            expectedDefaultImage,
					PostgresHost:     "postgres.test",
					PostgresUser:     "authentik",
					PostgresDatabase: "authentik",
					PostgresPasswordSecretRef: &authentikv1alpha1.SecretKeyReference{
						Name: "postgres-credentials", Key: "password",
					},
				},
				Status: authentikv1alpha1.AuthentikServerStatus{
					Conditions: []metav1.Condition{{Type: "RedisReady", Status: metav1.ConditionTrue}},
				},
			}
			bootstrap := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "authentik-bootstrap", Namespace: server.Namespace},
				Data: map[string][]byte{
					"token": []byte("token"), "password": []byte("password"),
					"secret-key": []byte("secret-key"), "email": []byte("admin@example.com"),
				},
			}
			objects := []client.Object{server, bootstrap}
			for _, component := range []string{"server", "worker"} {
				objects = append(objects, &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: server.Name + "-" + component, Namespace: server.Namespace},
					Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "authentik", Env: []corev1.EnvVar{{Name: "AUTHENTIK_REDIS__HOST", Value: "authentik-redis"}}}},
					}}},
				})
			}
			redisKey := types.NamespacedName{Name: server.Name + "-redis", Namespace: server.Namespace}
			resources := []client.Object{&appsv1.Deployment{}, &corev1.Service{}}
			for _, resource := range resources {
				resource.SetName(redisKey.Name)
				resource.SetUID(types.UID(tc.name + "-" + reflect.TypeOf(resource).String()))
				resource.SetNamespace(redisKey.Namespace)
				if tc.ownerUID != "" {
					resource.SetOwnerReferences([]metav1.OwnerReference{{
						APIVersion: authentikv1alpha1.GroupVersion.String(), Kind: "AuthentikServer",
						Name: server.Name, UID: tc.ownerUID, Controller: ptr.To(tc.controller),
					}})
				}
				if tc.exists {
					objects = append(objects, resource)
				}
			}
			r := &AuthentikServerReconciler{
				Client: fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(server).WithObjects(objects...).Build(),
				Scheme: scheme,
			}
			for range 2 {
				if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(server)}); err != nil {
					t.Fatal(err)
				}
				for _, resource := range resources {
					err := r.Get(ctx, redisKey, resource)
					if !tc.exists || tc.removed {
						if !apierrors.IsNotFound(err) {
							t.Fatalf("obsolete %T should be absent, got %v", resource, err)
						}
					} else if err != nil {
						t.Fatalf("foreign %T must be preserved: %v", resource, err)
					}
				}
				updated := &authentikv1alpha1.AuthentikServer{}
				if err := r.Get(ctx, client.ObjectKeyFromObject(server), updated); err != nil {
					t.Fatal(err)
				}
				if meta.FindStatusCondition(updated.Status.Conditions, "RedisReady") != nil {
					t.Fatal("obsolete Redis readiness condition remains")
				}
				for _, component := range []string{"server", "worker"} {
					deployment := &appsv1.Deployment{}
					if err := r.Get(ctx, types.NamespacedName{Name: server.Name + "-" + component, Namespace: server.Namespace}, deployment); err != nil {
						t.Fatal(err)
					}
					for _, env := range deployment.Spec.Template.Spec.Containers[0].Env {
						if env.Name == "AUTHENTIK_REDIS__HOST" {
							t.Fatalf("%s retains obsolete Redis configuration", component)
						}
					}
				}
				secret := &corev1.Secret{}
				if err := r.Get(ctx, client.ObjectKeyFromObject(bootstrap), secret); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(secret.Data, bootstrap.Data) {
					t.Fatal("existing bootstrap credentials changed")
				}
			}
		})
	}
}
