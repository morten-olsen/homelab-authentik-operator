package controller

import (
	"context"
	"testing"

	authentikv1alpha1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestServerStartupProbeSurvivesReconciliation(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, authentikv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	server := &authentikv1alpha1.AuthentikServer{
		ObjectMeta: metav1.ObjectMeta{Name: "authentik", Namespace: "shared", UID: "test-server"},
		Spec:       authentikv1alpha1.AuthentikServerSpec{Replicas: ptr.To(int32(1)), Image: "authentik:test"},
	}
	r := &AuthentikServerReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).Build(), Scheme: scheme}
	for range 2 {
		if err := r.reconcileAuthentikServerDeployment(context.Background(), server, "bootstrap"); err != nil {
			t.Fatal(err)
		}
		deployment := &appsv1.Deployment{}
		if err := r.Get(context.Background(), types.NamespacedName{Name: "authentik-server", Namespace: "shared"}, deployment); err != nil {
			t.Fatal(err)
		}
		container := deployment.Spec.Template.Spec.Containers[0]
		probe := container.StartupProbe
		if probe == nil || probe.HTTPGet == nil {
			t.Fatal("server needs an HTTP startup probe to gate liveness during slow database startup")
		}
		if probe.HTTPGet.Path != "/-/health/live/" || probe.HTTPGet.Port.IntValue() != 9000 {
			t.Fatalf("startup probe uses the wrong endpoint: %+v", probe.HTTPGet)
		}
		if probe.PeriodSeconds*probe.FailureThreshold != 600 || probe.TimeoutSeconds != 5 {
			t.Fatalf("expected a bounded ten-minute startup window with a five-second timeout, got %+v", probe)
		}
		if container.LivenessProbe.HTTPGet.Path != "/-/health/live/" || container.ReadinessProbe.HTTPGet.Path != "/-/health/ready/" {
			t.Fatal("startup protection must preserve ongoing liveness and readiness checks")
		}
	}
}
