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

// SecretKeyReference references a key in a Secret
type SecretKeyReference struct {
	// name is the name of the secret
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// namespace is the namespace of the secret. If not specified, uses the same namespace as the resource.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// key is the key in the secret to use.
	// +optional
	Key string `json:"key,omitempty"`
}

// TLSConfig defines TLS configuration for the Ingress
type TLSConfig struct {
	// enabled specifies whether TLS should be enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// secretName is the name of the secret containing TLS certificate and key
	// +optional
	SecretName string `json:"secretName,omitempty"`
}

// AuthentikServerSpec defines the desired state of AuthentikServer
type AuthentikServerSpec struct {
	// postgresHost is the PostgreSQL host
	// +optional
	PostgresHost string `json:"postgresHost,omitempty"`

	// postgresHostSecretRef references a secret containing the PostgreSQL host
	// +optional
	PostgresHostSecretRef *SecretKeyReference `json:"postgresHostSecretRef,omitempty"`

	// postgresUser is the PostgreSQL user
	// +optional
	PostgresUser string `json:"postgresUser,omitempty"`

	// postgresUserSecretRef references a secret containing the PostgreSQL user
	// +optional
	PostgresUserSecretRef *SecretKeyReference `json:"postgresUserSecretRef,omitempty"`

	// postgresName is the PostgreSQL database name
	// +optional
	PostgresName string `json:"postgresName,omitempty"`

	// postgresNameSecretRef references a secret containing the PostgreSQL database name
	// +optional
	PostgresNameSecretRef *SecretKeyReference `json:"postgresNameSecretRef,omitempty"`

	// postgresPassword is the PostgreSQL password
	// +optional
	PostgresPassword string `json:"postgresPassword,omitempty"`

	// postgresPasswordSecretRef references a secret containing the PostgreSQL password
	// +optional
	PostgresPasswordSecretRef *SecretKeyReference `json:"postgresPasswordSecretRef,omitempty"`

	// image is the Authentik container image to use
	// +optional
	// +kubebuilder:default="ghcr.io/goauthentik/server:latest"
	Image string `json:"image,omitempty"`

	// replicas is the number of Authentik server pods
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	Replicas *int32 `json:"replicas,omitempty"`

	// host is the external hostname for Authentik
	// +kubebuilder:validation:Required
	Host string `json:"host"`

	// tls configures TLS for the Ingress
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`
}

// AuthentikServerStatus defines the observed state of AuthentikServer.
type AuthentikServerStatus struct {
	// ready indicates whether the Authentik server is ready to accept connections
	Ready bool `json:"ready"`

	// url is the external URL of the Authentik server
	// +optional
	URL string `json:"url,omitempty"`

	// bootstrapSecretRef is the name of the secret containing bootstrap credentials
	// +optional
	BootstrapSecretRef string `json:"bootstrapSecretRef,omitempty"`

	// conditions represent the current state of the AuthentikServer resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// AuthentikServer is the Schema for the authentikservers API
type AuthentikServer struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of AuthentikServer
	// +required
	Spec AuthentikServerSpec `json:"spec"`

	// status defines the observed state of AuthentikServer
	// +optional
	Status AuthentikServerStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// AuthentikServerList contains a list of AuthentikServer
type AuthentikServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []AuthentikServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AuthentikServer{}, &AuthentikServerList{})
}
