# GitOps owns group membership and application access

Status: proposed for security review and staged rollout (HOMEIT-474).

## Decision

AuthentikGroup is namespaced in authentik.homelab.mortenolsen.pro/v1alpha1.
Its immutable serverRef selects one AuthentikServer. Its backing group is named
`gitops/<namespace>/<resource-name>`; an ownership attribute pins the Kubernetes
resource UID. An existing same-name group without that exact UID is a conflict,
including after deleting and recreating a Kubernetes resource. No adoption or
identity deletion is performed. Backing names must fit Authentik's 150 characters.

Only this resource owns its complete membership list. Members reference existing
human users by ID and UUID; renames remain valid, deleted/recreated identities do
not inherit access. Inactive users and service accounts are rejected. A missing
or invalid desired user clears existing direct membership and reports NotReady.
Managed fields include users, parents, roles, is_superuser=false and the owner
attribute. Undeclared child groups cause NotReady and application closure; the
operator never edits an unmanaged child to fix inheritance.

Deleting a managed group first clears its direct membership and privilege fields,
then removes its Kubernetes finalizer, retaining the Authentik identity and UID
claim. References to a deleted/not-ready group close applications. Missing remote
groups need no deletion action. Orphaned retained groups and policies need an
explicit later cleanup decision; recreation by name cannot silently adopt them.

AuthentikClient.allowedGroups references managed groups on the same server.
The client owns its application's binding set. There is no special group name or
superuser bypass in the operator. Charts always add their own application group;
extra groups extend it. A chart's oidc.group.members is the sole membership input
for its generated group. Central groups live in the shared chart, not in
competing membership resources.

## Access transition and failures

Authentik permits all users when there are no application bindings. ANY mode
also makes an old permissive binding an access bypass. Therefore each managed
application retains a constant-false policy binding. Before replacing bindings,
the operator installs/verifies this guard and switches the application to ALL.
It then verifies all group ownership, exact memberships, privileges, hierarchy
and ready generations, checks the complete legacy binding inventory, replaces
bindings, reads back the exact result and switches to ANY. New applications are
created without a provider and attached only after successful access setup.
Errors after application ownership is established also attempt to disconnect the
provider and set ALL; failure to reach Authentik is explicitly reported, not
claimed to have revoked access. Earlier errors cannot claim fail-closed state.

Existing applications are claimed only using the originating client's recorded
application slug and provider ID, then marked with the client UID in the managed
application description. New disconnected applications carry that description
from creation, allowing restart recovery without blind adoption. Only explicitly
inventoried pre-migration bindings in replacesBindings may be removed. Once
managed, group-binding edits are drift; unknown policy/user bindings leave the
application closed for investigation rather than deleting unrelated policy.

Access opt-in is sticky in Kubernetes status and the Authentik guard. An explicit
empty list denies access, as does omission after opt-in. Existing legacy clients
with recorded providers and no opt-in keep their old access during staging;
AccessReady=Unknown/LegacyAccessUnmanaged exposes this exception. New clients
with no allowed list are denied. The upgrade must migrate every legacy client;
the exception is not the final intended state.

Group changes enqueue referencing clients. Periodic reconciliation (30 seconds
on success) repairs UI drift and restart state. No instantaneous revocation is
promised while either Kubernetes or Authentik is unreachable; retained enforcement
and conditions must be inspected. Application sessions and issued tokens are
separate from new authorization and are not revoked by a membership edit.

## Alternatives

Managing membership in Authentik's UI was superseded by Morten's GitOps ownership
decision. Referencing/adopting the existing privileged group admin was rejected:
application access must not grant Authentik superuser privileges. A separate
AuthentikGroup named admin is deployment configuration, not operator behavior.
Username-only membership was rejected because renames and identity recreation
would change who receives access. Independent membership resources were rejected
because multiple writers could own the same list.

Disconnecting providers alone would prevent new logins during updates, but would
leave empty application bindings with permissive dashboard access and would not
protect deletion of the last grant. The permanent guard preserves explicit deny
semantics; disconnection is an additional recovery measure on failure.

## Delivery and rollback

Merge is gated by security review, green CI and explicit release approval:
main's existing mirrored workflow publishes a tag, image, release and Helm chart.
CRDs/operator precede semantic groups; establish the administrator group before
cutting over one application at a time. Application rollout needs its own agreed
staging decision. The task records the inventory and live authorization evidence.

Rollback a failed application cutover before diagnosing. Retain group and guard
objects and provider credentials; do not delete groups or revert to an operator
that resets applications to ANY without understanding the access consequences.
A Git revert alone does not undo Authentik membership/binding changes or revoke
existing application sessions. Recovery is an explicit access configuration change,
never automatic adoption or deletion of pre-existing identity data.

Sources: [application access](https://docs.goauthentik.io/add-secure-apps/applications/manage_apps/),
[group inheritance](https://docs.goauthentik.io/users-sources/groups/).
