package controller

import (
	authv1 "github.com/mortenolsen/operator-authentik/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Group API schema", func() {
	It("pins user identities and rejects a server move", func() {
		group := &authv1.AuthentikGroup{ObjectMeta: metav1.ObjectMeta{Name: "schema-test", Namespace: "default"}, Spec: authv1.AuthentikGroupSpec{ServerRef: authv1.NamespacedName{Name: "authentik", Namespace: "shared"}, Members: []authv1.ExistingUserReference{{ID: 7, UUID: "d8359fc2-7656-45d2-a22e-5cbd13cb941f"}}}}
		Expect(k8sClient.Create(ctx, group)).To(Succeed())
		group.Spec.ServerRef.Name = "other"
		Expect(k8sClient.Update(ctx, group)).NotTo(Succeed())
		group.Spec.ServerRef.Name = "authentik"
		group.Spec.Members[0].UUID = "not-a-uuid"
		Expect(k8sClient.Update(ctx, group)).NotTo(Succeed())
		group.Spec.Members = nil
		Expect(k8sClient.Update(ctx, group)).To(Succeed())
		Expect(k8sClient.Delete(ctx, group)).To(Succeed())
	})
})
