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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authentikv1alpha1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
)

var _ = Describe("AuthentikServer Controller", func() {
	const (
		resourceName      = "test-authentik-server"
		resourceNamespace = "default"
		postgresSecret    = "test-postgres-secret"
		testHost          = "auth.test.example.com"

		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When reconciling a resource", func() {
		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
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

			By("creating the custom resource for the Kind AuthentikServer")
			authentikserver := &authentikv1alpha1.AuthentikServer{}
			err = k8sClient.Get(ctx, typeNamespacedName, authentikserver)
			if err != nil && errors.IsNotFound(err) {
				resource := &authentikv1alpha1.AuthentikServer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
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
						PostgresNameSecretRef: &authentikv1alpha1.SecretKeyReference{
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
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &authentikv1alpha1.AuthentikServer{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				By("Cleanup the specific resource instance AuthentikServer")
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}

			// Clean up the postgres secret
			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: postgresSecret, Namespace: resourceNamespace}, secret)
			if err == nil {
				Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			}
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &AuthentikServerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking that the bootstrap secret was created")
			bootstrapSecret := &corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      resourceName + "-bootstrap",
					Namespace: resourceNamespace,
				}, bootstrapSecret)
			}, timeout, interval).Should(Succeed())

			Expect(bootstrapSecret.Data).To(HaveKey("token"))
			Expect(bootstrapSecret.Data).To(HaveKey("password"))
			Expect(bootstrapSecret.Data).To(HaveKey("secret-key"))
			Expect(bootstrapSecret.Data).To(HaveKey("email"))

			By("Checking that the Redis deployment was created")
			redisDeployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      resourceName + "-redis",
					Namespace: resourceNamespace,
				}, redisDeployment)
			}, timeout, interval).Should(Succeed())

			By("Checking that the Redis service was created")
			redisService := &corev1.Service{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      resourceName + "-redis",
					Namespace: resourceNamespace,
				}, redisService)
			}, timeout, interval).Should(Succeed())

			By("Checking that the Authentik deployment was created")
			authentikDeployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      resourceName,
					Namespace: resourceNamespace,
				}, authentikDeployment)
			}, timeout, interval).Should(Succeed())

			By("Checking that the Authentik service was created")
			authentikService := &corev1.Service{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      resourceName,
					Namespace: resourceNamespace,
				}, authentikService)
			}, timeout, interval).Should(Succeed())

			By("Checking that the status was updated")
			updatedServer := &authentikv1alpha1.AuthentikServer{}
			Eventually(func() string {
				err := k8sClient.Get(ctx, typeNamespacedName, updatedServer)
				if err != nil {
					return ""
				}
				return updatedServer.Status.BootstrapSecretRef
			}, timeout, interval).Should(Equal(resourceName + "-bootstrap"))
		})
	})
})
