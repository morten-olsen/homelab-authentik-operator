package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	authentikv1alpha1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"
)

const expectedDefaultImage = "ghcr.io/goauthentik/server:2026.8.5"

func TestServerImageDefaultAndOverride(t *testing.T) {
	for _, tc := range []struct{ name, image, want string }{
		{"omitted", "", expectedDefaultImage},
		{"explicit", "ghcr.io/goauthentik/server:2026.8.3", "ghcr.io/goauthentik/server:2026.8.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, authentikv1alpha1.AddToScheme} {
				if err := add(scheme); err != nil {
					t.Fatal(err)
				}
			}
			server := &authentikv1alpha1.AuthentikServer{
				ObjectMeta: metav1.ObjectMeta{Name: "authentik", Namespace: "test", UID: "test"},
				Spec:       authentikv1alpha1.AuthentikServerSpec{Image: tc.image},
			}
			r := &AuthentikServerReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).Build(), Scheme: scheme}
			for range 2 {
				r.applyDefaults(server)
				if server.Spec.Image != tc.want {
					t.Fatalf("image = %q, want %q", server.Spec.Image, tc.want)
				}
				if err := r.reconcileAuthentikServerDeployment(context.Background(), server, "bootstrap"); err != nil {
					t.Fatal(err)
				}
				if err := r.reconcileAuthentikWorkerDeployment(context.Background(), server, "bootstrap"); err != nil {
					t.Fatal(err)
				}
				for _, component := range []string{"server", "worker"} {
					deployment := &appsv1.Deployment{}
					if err := r.Get(context.Background(), types.NamespacedName{Name: "authentik-" + component, Namespace: "test"}, deployment); err != nil {
						t.Fatal(err)
					}
					if got := deployment.Spec.Template.Spec.Containers[0].Image; got != tc.want {
						t.Fatalf("%s image = %q, want %q", component, got, tc.want)
					}
				}
			}
		})
	}
}

func TestPackagedCRDImageDefaults(t *testing.T) {
	for _, dir := range []string{"config/crd/bases", "charts/authentik-operator/crds"} {
		t.Run(dir, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../..", dir, "authentik.homelab.mortenolsen.pro_authentikservers.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var crd apiextensionsv1.CustomResourceDefinition
			if err := yaml.Unmarshal(data, &crd); err != nil {
				t.Fatal(err)
			}
			for _, version := range crd.Spec.Versions {
				image := version.Schema.OpenAPIV3Schema.Properties["spec"].Properties["image"]
				if image.Default == nil || string(image.Default.Raw) != `"`+expectedDefaultImage+`"` {
					t.Fatalf("%s image default = %v, want %q", version.Name, image.Default, expectedDefaultImage)
				}
			}
		})
	}
}
