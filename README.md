# operator-authentik
// TODO(user): Add simple overview of use/purpose

## Description
// TODO(user): An in-depth paragraph about your project and overview of use

## Authentik server image default

New `AuthentikServer` resources that omit `spec.image` use
`ghcr.io/goauthentik/server:2026.8.5` for both server and worker. This is the
current patch in the supported 2026.8 release series as of 2026-10-24; see the
[upstream release notes](https://docs.goauthentik.io/releases/2026.8/).
The registry does not publish a `latest` tag.

Keep the default on a fixed supported release. Update it through a reviewed
change after checking upstream release/support notes and registry availability;
regenerate `config/crd/bases`, copy the server CRD into the Helm chart, and run
`make test`, `make test-e2e` and chart validation. The fallback, API marker,
packaged CRDs and E2E expectations must agree. Repository Renovate runs weekly
on Sunday at 03:15 UTC and tracks the operator's image defaults; core's Renovate
updates explicit workload image pins separately. An explicit `spec.image` is
preserved, including an older version or `latest`; changing the default does not
rewrite existing pins. Operators should
pin existing stateful installations explicitly and approve upgrades separately.
The homelab is pinned to `2026.8.5`; removing its obsolete Redis workload does not
migrate the database or change its credentials.

## Supported Authentik versions and dependencies

Use Authentik 2025.10 or newer; the deployed supported release series is 2026.8.x.
Authentik [removed Redis in 2025.10](https://docs.goauthentik.io/releases/2025.10/#redis-removal)
and now uses PostgreSQL for caching, tasks and sessions. The operator creates no
Redis workload or Redis environment settings. On reconciliation it deletes an
obsolete `<server-name>-redis` Deployment and Service only when controlled by
that `AuthentikServer` UID; unowned resources and resources controlled by another
server are left untouched. PostgreSQL configuration and bootstrap credentials
are preserved.

## Server startup health checks

The server's HTTP startup probe checks `/-/health/live/` on port 9000 every ten
seconds, with a five-second request timeout and 60 failures allowed. Kubernetes
holds liveness and readiness probes until startup succeeds, giving the server
up to ten minutes to start while PostgreSQL and the migration worker recover
after a reboot. After startup, the existing live and ready endpoints continue
to check the running server. Readiness still controls whether it receives traffic.

This startup budget prevents premature liveness restarts; database contention
must also be fixed in the postgres operator. It does not make a permanent lock
deadlock safe.

## Getting Started

### Release version and approval

The mirror's main workflow publishes the version in
`charts/authentik-operator/Chart.yaml` as its `v` tag, image tag and chart version.
Bump `version` and `appVersion` together before a release-triggering merge. The
workflow refuses an existing tag; it must never overwrite an existing release.
This avoids inferring `0.1.0` from stale `v0.0.15` tag history when `0.1.0`
artifacts already exist. Redis removal is prepared as `0.1.4`, following
the published default-image release `0.1.3`.
Renovate source PRs still require review and a matching chart `version` and
`appVersion` bump before the release-triggering merge.

Morten must approve the repository, version, commit and publishing/deployment
effects before merging to main. Publication alone does not update the homelab:
once the artifacts exist, change core's pinned operator version and verify the
operator image and the generated server startup probe in the cluster.

### Prerequisites
- go version v1.24.6+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/operator-authentik:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/operator-authentik:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/operator-authentik:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/operator-authentik/<tag or branch>/dist/install.yaml
```

### By providing a Helm Chart

1. Build the chart using the optional helm plugin

```sh
kubebuilder edit --plugins=helm/v2-alpha
```

2. See that a chart was generated under 'dist/chart', and users
can obtain this solution from there.

**NOTE:** If you change the project, you need to update the Helm Chart
using the same command above to sync the latest changes. Furthermore,
if you create webhooks, you need to use the above command with
the '--force' flag and manually ensure that any custom configuration
previously added to 'dist/chart/values.yaml' or 'dist/chart/manager/manager.yaml'
is manually re-applied afterwards.

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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

### End-to-end test fixtures

`make test-e2e` runs the operator in an isolated Kind cluster. The server fixture
omits `spec.image`, checks admission and both deployment images are `2026.8.5`,
then waits for both deployments and `status.ready=true`. The client test reuses
that initialized server and its bootstrap secret. A second server against the
same test database would generate credentials that differ from its first-boot
initialization. Explicit image preservation is tested separately in the
controller regression tests.

The suite has a thirty-minute Go timeout so image builds, startup waits and
failure diagnostics fit inside the overall deadline. Individual readiness waits
remain bounded. Fixtures also check the public HTTPS URL and startup probe,
and delete clients and servers before undeploying the controller so their
finalizers can finish. Namespace cleanup has a bounded wait. Runtime credentials
and data are not used by these isolated tests.

## GitOps groups and access

Operator 0.2.0 adds `AuthentikGroup` and `AuthentikClient.allowedGroups`. See
[ownership and cutover rules](docs/adr/0001-gitops-groups-and-access.md) before
upgrading. User provisioning is outside this feature.

```yaml
apiVersion: authentik.homelab.mortenolsen.pro/v1alpha1
kind: AuthentikGroup
metadata:
  name: app-access
  namespace: prod
spec:
  serverRef: {name: authentik, namespace: shared}
  members:
    - id: 123
      uuid: 11111111-2222-4333-8444-555555555555
```

Reference it from a client with
`allowedGroups: [{name: app-access, namespace: prod}]`. An empty list denies
access. Once a client has opted in, removing the list also denies access.
The group owns its complete direct membership; UI edits are drift. Backing groups
never grant Authentik superuser or role privileges, and the operator has no
special `admin` behavior. Inspect user IDs/UUIDs through the authenticated
Authentik API without logging credentials; never identify members by display name.

Local and Woodpecker PR validation uses `mise install && task ci:quality`
(build, `make test` including envtest, generated CRD/RBAC drift and Helm rendering).
The service-image delivery shape and existing GitHub mirror release workflow are
preserved: merging main publishes the reviewed chart version and requires release
approval. The new quality workflow uses the existing ci/mise image and no secrets;
it does not publish or change release mechanics.
