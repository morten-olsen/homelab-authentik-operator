package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AuthentikProxyProviderSpec declares a forward-auth proxy provider served by the
// server's embedded outpost, for applications protected by a reverse proxy
// (for example Istio ext_authz) instead of speaking OIDC themselves.
type AuthentikProxyProviderSpec struct {
	// serverRef references the AuthentikServer to create the provider on
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="serverRef is immutable"
	ServerRef NamespacedName `json:"serverRef"`

	// name is the display name of the application in Authentik
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// externalHost is the URL users open, including scheme, for example
	// https://app.example.com. The outpost matches requests by this host.
	// +required
	// +kubebuilder:validation:Pattern=`^https?://[^/]+$`
	ExternalHost string `json:"externalHost"`

	// mode is the forward-auth mode. forward_single protects exactly
	// externalHost with its own application and access bindings.
	// +optional
	// +kubebuilder:default="forward_single"
	// +kubebuilder:validation:Enum=forward_single
	Mode string `json:"mode,omitempty"`

	// accessTokenValidity bounds how long an outpost session stays valid without
	// a new authorization, in Authentik's duration syntax (for example hours=8).
	// Removing someone from an allowed group blocks new logins but not a live
	// session, so keep this short.
	// +optional
	// +kubebuilder:default="hours=8"
	// +kubebuilder:validation:Pattern=`^((weeks|days|hours|minutes|seconds)=[0-9]+;?)+$`
	AccessTokenValidity string `json:"accessTokenValidity,omitempty"`

	// allowedGroups grants access when any listed AuthentikGroup matches.
	// Omission and an explicitly empty list both deny access.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	AllowedGroups []NamespacedName `json:"allowedGroups,omitempty"`
}

// AuthentikProxyProviderStatus defines the observed state of AuthentikProxyProvider.
type AuthentikProxyProviderStatus struct {
	// ready indicates whether the provider is attached and access is verified
	Ready bool `json:"ready"`

	// observedGeneration is the generation last reconciled successfully
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// providerID is the Authentik proxy provider ID
	// +optional
	ProviderID int `json:"providerId,omitempty"`

	// applicationID is the Authentik application slug
	// +optional
	ApplicationID string `json:"applicationId,omitempty"`

	// outpostID is the embedded outpost the provider is attached to
	// +optional
	OutpostID string `json:"outpostId,omitempty"`

	// conditions represent the current state of the AuthentikProxyProvider resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.externalHost`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Provider",type=integer,JSONPath=`.status.providerId`

// AuthentikProxyProvider is the Schema for the authentikproxyproviders API
type AuthentikProxyProvider struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of AuthentikProxyProvider
	// +required
	Spec AuthentikProxyProviderSpec `json:"spec"`

	// status defines the observed state of AuthentikProxyProvider
	// +optional
	Status AuthentikProxyProviderStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// AuthentikProxyProviderList contains a list of AuthentikProxyProvider
type AuthentikProxyProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []AuthentikProxyProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AuthentikProxyProvider{}, &AuthentikProxyProviderList{})
}
