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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NamespacedName represents a namespaced name reference
type NamespacedName struct {
	// name is the name of the resource
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// namespace is the namespace of the resource
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`
}

// AuthentikClientSpec defines the desired state of AuthentikClient
type AuthentikClientSpec struct {
	// serverRef references the AuthentikServer to create the client on
	// +kubebuilder:validation:Required
	ServerRef NamespacedName `json:"serverRef"`

	// name is the display name for the OAuth2 client in Authentik
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// redirectUris are the allowed redirect URIs for the client
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	RedirectURIs []string `json:"redirectUris"`

	// clientType is the OAuth2 client type (confidential or public)
	// +optional
	// +kubebuilder:default="confidential"
	// +kubebuilder:validation:Enum=confidential;public
	ClientType string `json:"clientType,omitempty"`

	// scopes are the allowed OAuth2 scopes
	// +optional
	// +kubebuilder:default={"openid","profile","email"}
	Scopes []string `json:"scopes,omitempty"`

	// secretName is the name of the secret to create with OIDC credentials.
	// Defaults to <client-name>-oidc-credentials
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// authentikUrl is the base URL for the Authentik server API and OIDC endpoints.
	// If provided, this URL is used instead of constructing from the AuthentikServer's host.
	// Example: http://my-server:7000
	// +optional
	AuthentikURL string `json:"authentikUrl,omitempty"`

	// clientId is the OAuth2 client ID to use.
	// If provided, this client ID will be used instead of the randomly generated one.
	// +optional
	ClientID string `json:"clientId,omitempty"`
}

// AuthentikClientStatus defines the observed state of AuthentikClient.
type AuthentikClientStatus struct {
	// ready indicates whether the OIDC client is ready
	Ready bool `json:"ready"`

	// clientID is the OAuth2 client ID
	// +optional
	ClientID string `json:"clientId,omitempty"`

	// providerID is the Authentik provider ID
	// +optional
	ProviderID int `json:"providerId,omitempty"`

	// applicationID is the Authentik application slug
	// +optional
	ApplicationID string `json:"applicationId,omitempty"`

	// secretName is the name of the secret containing OIDC credentials
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// conditions represent the current state of the AuthentikClient resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// AuthentikClient is the Schema for the authentikclients API
type AuthentikClient struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of AuthentikClient
	// +required
	Spec AuthentikClientSpec `json:"spec"`

	// status defines the observed state of AuthentikClient
	// +optional
	Status AuthentikClientStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// AuthentikClientList contains a list of AuthentikClient
type AuthentikClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []AuthentikClient `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AuthentikClient{}, &AuthentikClientList{})
}
