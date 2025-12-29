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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authentikv1alpha1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
)

var _ = Describe("AuthentikClient Controller", func() {
	const (
		clientName        = "test-authentik-client"
		serverName        = "test-authentik-server-for-client"
		resourceNamespace = "default"
		postgresSecret    = "test-postgres-secret-client"
		testHost          = "auth.test.example.com"

		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When reconciling a resource", func() {
		ctx := context.Background()

		clientNamespacedName := types.NamespacedName{
			Name:      clientName,
			Namespace: resourceNamespace,
		}

		serverNamespacedName := types.NamespacedName{
			Name:      serverName,
			Namespace: resourceNamespace,
		}

		BeforeEach(func() {
			By("creating the postgres secret")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      postgresSecret,
					Namespace: resourceNamespace,
				},
				StringData: map[string]string{
					"host":     "localhost",
					"user":     "authentik",
					"name":     "authentik",
					"password": "authentik-password",
				},
			}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: postgresSecret, Namespace: resourceNamespace}, &corev1.Secret{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			}

			By("creating an AuthentikServer for the client to reference")
			server := &authentikv1alpha1.AuthentikServer{}
			err = k8sClient.Get(ctx, serverNamespacedName, server)
			if err != nil && errors.IsNotFound(err) {
				server = &authentikv1alpha1.AuthentikServer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      serverName,
						Namespace: resourceNamespace,
					},
					Spec: authentikv1alpha1.AuthentikServerSpec{
						PostgresHostSecretRef: &authentikv1alpha1.SecretKeyReference{
							Name: postgresSecret,
							Key:  "host",
						},
						PostgresUserSecretRef: &authentikv1alpha1.SecretKeyReference{
							Name: postgresSecret,
							Key:  "user",
						},
						PostgresDatabaseSecretRef: &authentikv1alpha1.SecretKeyReference{
							Name: postgresSecret,
							Key:  "name",
						},
						PostgresPasswordSecretRef: &authentikv1alpha1.SecretKeyReference{
							Name: postgresSecret,
							Key:  "password",
						},
						Host: testHost,
					},
				}
				Expect(k8sClient.Create(ctx, server)).To(Succeed())
			}

			By("creating the custom resource for the Kind AuthentikClient")
			authentikclient := &authentikv1alpha1.AuthentikClient{}
			err = k8sClient.Get(ctx, clientNamespacedName, authentikclient)
			if err != nil && errors.IsNotFound(err) {
				resource := &authentikv1alpha1.AuthentikClient{
					ObjectMeta: metav1.ObjectMeta{
						Name:      clientName,
						Namespace: resourceNamespace,
					},
					Spec: authentikv1alpha1.AuthentikClientSpec{
						ServerRef: authentikv1alpha1.NamespacedName{
							Name:      serverName,
							Namespace: resourceNamespace,
						},
						Name: "Test Application",
						RedirectURIs: []string{
							"https://app.example.com/callback",
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// Clean up client
			client := &authentikv1alpha1.AuthentikClient{}
			err := k8sClient.Get(ctx, clientNamespacedName, client)
			if err == nil {
				By("Cleanup the specific resource instance AuthentikClient")
				if len(client.Finalizers) > 0 {
					client.Finalizers = nil
					Expect(k8sClient.Update(ctx, client)).To(Succeed())
				}
				Expect(k8sClient.Delete(ctx, client)).To(Succeed())
			}

			// Clean up server
			server := &authentikv1alpha1.AuthentikServer{}
			err = k8sClient.Get(ctx, serverNamespacedName, server)
			if err == nil {
				By("Cleanup the AuthentikServer")
				Expect(k8sClient.Delete(ctx, server)).To(Succeed())
			}

			// Clean up the postgres secret
			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: postgresSecret, Namespace: resourceNamespace}, secret)
			if err == nil {
				Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			}
		})

		It("should wait for server to be ready before proceeding", func() {
			By("Reconciling the created resource when server is not ready")
			controllerReconciler := &AuthentikClientReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: clientNamespacedName,
			})
			// Should requeue because server is not ready
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			By("Checking that the client status reflects server not ready")
			client := &authentikv1alpha1.AuthentikClient{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, clientNamespacedName, client)
				if err != nil {
					return false
				}
				for _, cond := range client.Status.Conditions {
					if cond.Type == "ServerReady" && cond.Status == metav1.ConditionFalse {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})

		It("should add finalizer to the resource", func() {
			By("Reconciling to add finalizer")
			controllerReconciler := &AuthentikClientReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: clientNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking that the finalizer was added")
			client := &authentikv1alpha1.AuthentikClient{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, clientNamespacedName, client)
				if err != nil {
					return false
				}
				for _, f := range client.Finalizers {
					if f == authentikClientFinalizer {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})
	})
})
