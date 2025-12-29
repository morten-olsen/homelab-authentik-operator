//go:build e2e
// +build e2e

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

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/mortenolsen/operator-authentik/test/utils"
)

// namespace where the project is deployed in
const namespace = "operator-authentik-system"

// serviceAccountName created for the project
const serviceAccountName = "operator-authentik-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "operator-authentik-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "operator-authentik-metrics-binding"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("deploying postgres")
		cmd = exec.Command("kubectl", "apply", "-f", "test/e2e/postgres.yaml", "-n", namespace)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy postgres")

		By("waiting for postgres to be ready")
		cmd = exec.Command("kubectl", "wait", "deployment/postgres", "--for=condition=Available", "--timeout=300s", "-n", namespace)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Postgres did not become ready")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the ClusterRoleBinding for metrics")
		cmd := exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName)
		_, _ = utils.Run(cmd)

		By("cleaning up the curl pod for metrics")
		cmd = exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=operator-authentik-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("ensuring the controller pod is ready")
			verifyControllerPodReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Controller pod not ready")
			}
			Eventually(verifyControllerPodReady, 3*time.Minute, time.Second).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Serving metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted, 3*time.Minute, time.Second).Should(Succeed())

			// +kubebuilder:scaffold:e2e-metrics-webhooks-readiness

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			verifyMetricsAvailable := func(g Gomega) {
				metricsOutput, err := getMetricsOutput()
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
				g.Expect(metricsOutput).NotTo(BeEmpty())
				g.Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
			}
			Eventually(verifyMetricsAvailable, 2*time.Minute).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks

		It("should reconcile an AuthentikServer CR", func() {
			By("creating the postgres secret")
			cmd := exec.Command("kubectl", "create", "secret", "generic", "e2e-postgres-secret",
				"--from-literal=host=postgres",
				"--from-literal=user=authentik",
				"--from-literal=name=authentik",
				"--from-literal=password=authentik",
				"-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create postgres secret")

			By("applying the AuthentikServer CR")
			authentikServerYAML := `
apiVersion: authentik.homelab.mortenolsen.pro/v1alpha1
kind: AuthentikServer
metadata:
  name: e2e-test-server
  namespace: ` + namespace + `
spec:
  postgresHostSecretRef:
    name: e2e-postgres-secret
    key: host
  postgresUserSecretRef:
    name: e2e-postgres-secret
    key: user
  postgresNameSecretRef:
    name: e2e-postgres-secret
    key: name
  postgresPasswordSecretRef:
    name: e2e-postgres-secret
    key: password
  host: auth.e2e-test.local
`
			// Write YAML to temp file
			tmpFile := filepath.Join("/tmp", "authentikserver-e2e.yaml")
			err = os.WriteFile(tmpFile, []byte(authentikServerYAML), 0644)
			Expect(err).NotTo(HaveOccurred(), "Failed to write AuthentikServer YAML")

			cmd = exec.Command("kubectl", "apply", "-f", tmpFile)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply AuthentikServer CR")

			By("verifying that the AuthentikServer CR is created")
			verifyServerCreated := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "authentikserver", "e2e-test-server",
					"-n", namespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("e2e-test-server"))
			}
			Eventually(verifyServerCreated, 30*time.Second, time.Second).Should(Succeed())

			By("verifying that the bootstrap secret was created")
			verifyBootstrapSecret := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", "e2e-test-server-bootstrap",
					"-n", namespace, "-o", "jsonpath={.data.token}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty())
			}
			Eventually(verifyBootstrapSecret, 60*time.Second, time.Second).Should(Succeed())

			By("verifying that the Redis deployment was created")
			verifyRedisDeployment := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment", "e2e-test-server-redis",
					"-n", namespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("e2e-test-server-redis"))
			}
			Eventually(verifyRedisDeployment, 60*time.Second, time.Second).Should(Succeed())

			By("verifying that the Authentik deployment was created")
			verifyAuthentikDeployment := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment", "e2e-test-server-server",
					"-n", namespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("e2e-test-server-server"))
			}
			Eventually(verifyAuthentikDeployment, 60*time.Second, time.Second).Should(Succeed())

			By("verifying that the Authentik service was created")
			verifyAuthentikService := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "service", "e2e-test-server",
					"-n", namespace, "-o", "jsonpath={.spec.ports[0].port}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("9000"))
			}
			Eventually(verifyAuthentikService, 60*time.Second, time.Second).Should(Succeed())

			By("verifying that the status URL is set")
			verifyStatusURL := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "authentikserver", "e2e-test-server",
					"-n", namespace, "-o", "jsonpath={.status.url}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("http://auth.e2e-test.local"))
			}
			Eventually(verifyStatusURL, 60*time.Second, time.Second).Should(Succeed())

			By("cleaning up the AuthentikServer CR")
			cmd = exec.Command("kubectl", "delete", "authentikserver", "e2e-test-server", "-n", namespace)
			_, _ = utils.Run(cmd)

			By("cleaning up the postgres secret")
			cmd = exec.Command("kubectl", "delete", "secret", "e2e-postgres-secret", "-n", namespace)
			_, _ = utils.Run(cmd)
		})

		It("should reconcile an AuthentikClient CR", func() {
			By("creating the postgres secret")
			cmd := exec.Command("kubectl", "create", "secret", "generic", "e2e-postgres-secret-client",
				"--from-literal=host=postgres",
				"--from-literal=user=authentik",
				"--from-literal=name=authentik",
				"--from-literal=password=authentik",
				"-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("applying the AuthentikServer CR")
			authentikServerYAML := `
apiVersion: authentik.homelab.mortenolsen.pro/v1alpha1
kind: AuthentikServer
metadata:
  name: e2e-test-server-client
  namespace: ` + namespace + `
spec:
  postgresHostSecretRef:
    name: e2e-postgres-secret-client
    key: host
  postgresUserSecretRef:
    name: e2e-postgres-secret-client
    key: user
  postgresNameSecretRef:
    name: e2e-postgres-secret-client
    key: name
  postgresPasswordSecretRef:
    name: e2e-postgres-secret-client
    key: password
  host: auth-client.e2e-test.local
`
			tmpServerFile := filepath.Join("/tmp", "authentikserver-client-e2e.yaml")
			err = os.WriteFile(tmpServerFile, []byte(authentikServerYAML), 0644)
			Expect(err).NotTo(HaveOccurred())
			cmd = exec.Command("kubectl", "apply", "-f", tmpServerFile)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("applying the AuthentikClient CR")
			authentikClientYAML := `
apiVersion: authentik.homelab.mortenolsen.pro/v1alpha1
kind: AuthentikClient
metadata:
  name: e2e-test-client
  namespace: ` + namespace + `
spec:
  serverRef:
    name: e2e-test-server-client
    namespace: ` + namespace + `
  name: "Test Client"
  redirectUris:
    - https://app.e2e-test.local/callback
`
			tmpClientFile := filepath.Join("/tmp", "authentikclient-e2e.yaml")
			err = os.WriteFile(tmpClientFile, []byte(authentikClientYAML), 0644)
			Expect(err).NotTo(HaveOccurred())
			cmd = exec.Command("kubectl", "apply", "-f", tmpClientFile)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying that the AuthentikClient CR is created")
			verifyClientCreated := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "authentikclient", "e2e-test-client",
					"-n", namespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("e2e-test-client"))
			}
			Eventually(verifyClientCreated, 30*time.Second, time.Second).Should(Succeed())

			By("verifying that the server is eventually ready")
			verifyServerReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "authentikserver", "e2e-test-server-client",
					"-n", namespace, "-o", "jsonpath={.status.ready}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"))
			}
			Eventually(verifyServerReady, 5*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying that the client is eventually ready")
			verifyClientReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "authentikclient", "e2e-test-client",
					"-n", namespace, "-o", "jsonpath={.status.ready}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"))
			}
			Eventually(verifyClientReady, 5*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up the AuthentikClient and AuthentikServer")
			cmd = exec.Command("kubectl", "delete", "authentikclient", "e2e-test-client", "-n", namespace)
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "authentikserver", "e2e-test-server-client", "-n", namespace)
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "secret", "e2e-postgres-secret-client", "-n", namespace)
			_, _ = utils.Run(cmd)
		})
	})
})

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	return utils.Run(cmd)
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
