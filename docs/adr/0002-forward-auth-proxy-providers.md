# Forward-auth proxy providers on the embedded outpost

Status: accepted by Morten for implementation (Mission Control task 50ce4193).

## Decision

AuthentikProxyProvider (namespaced, authentik.homelab.mortenolsen.pro/v1alpha1)
declares an Authentik proxy provider in `forward_single` mode for one external
host. A reverse proxy in front of the application, normally an Istio sidecar
`CUSTOM` AuthorizationPolicy using an `envoyExtAuthzHttp` provider, asks the
outpost whether a request may pass. Applications without OIDC support can then
sit behind Authentik without any configuration in Authentik's UI.

Access uses the ADR 0001 machinery unchanged. The application slug is
`<namespace>-<name>`; it is created disconnected in ALL mode with the
constant-false guard, its exact `allowedGroups` bindings are verified, and only
then is the provider attached. There is no legacy mode: omitting
`allowedGroups` or listing none denies access. The application description
keeps the historical `Managed by AuthentikClient <uid>` claim text; the UID is
the claim, and it is unique across kinds. Group enforcement happens in
Authentik's authorization flow. The reverse proxy never inspects claims.

The provider is named `<namespace>-<name>`. The operator only ever modifies or
deletes the provider it created, identified by its ID in status or, if status
was lost, in the `authentik.homelab.mortenolsen.pro/provider-id` annotation,
which is written before the provider is attached anywhere. A provider that only
matches by name is never adopted: reconciliation stops with a conflict, as
does a recorded provider now assigned to another application. The operator
owns the provider's name, flows, external host, mode and access token
validity; drift is patched and read back.

The outpost selects a provider by host, so one external host belongs to one
resource per server. The oldest resource claiming a host keeps it; newer ones
report `HostConflict` and create nothing. Charts should name these resources
distinctly from their AuthentikClient (homelab-common uses
`<release>-forward-auth`), because both kinds derive the application slug from
namespace and name, and a shared slug stalls both on the ownership check.

The embedded outpost is shared. The operator adds or removes only the provider
IDs it owns in the outpost's `providers` list, carries every other entry and
config key over unchanged, and reads back the result. It also owns one config
key, `authentik_host`, set to `https://<AuthentikServer.spec.host>` so browser
redirects never use plain HTTP. A dedicated outpost per server was rejected for
now: it adds a workload, an outpost image version to keep in step with the
server, and memory on a single node, while logins still depend on the server.

`accessTokenValidity` (default `hours=8`) bounds outpost sessions. Removing a
user from a group blocks new authorizations but does not end a live session,
exactly as for OIDC sessions in ADR 0001.

## Failure and deletion

An access failure disconnects the provider from the application (ReconcileAccess
closes it in ALL mode) before any provider or outpost change. A new resource
never creates a provider until access is verified. Provider identity is written
to status before the provider is attached to the application or outpost.

Deletion detaches the provider from the outpost, deletes the application only
while it still carries this UID's claim, then deletes the provider. The
finalizer is retained while Authentik or the bootstrap secret is unavailable.
It is released without Authentik cleanup only when the referenced
AuthentikServer itself no longer exists. The guard policy is retained, as in
ADR 0001.

## Delivery

Released as operator 0.3.0 through docs/releases.md. The Istio extension
provider and the per-application AuthorizationPolicy, VirtualService callback
route and CR live in homelab/core (homelab-common) and are not part of this
operator.
