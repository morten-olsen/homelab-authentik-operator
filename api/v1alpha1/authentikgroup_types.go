package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ExistingUserReference identifies an existing Authentik human user. The UUID
// prevents a renamed/recreated user from receiving an earlier user's access.
type ExistingUserReference struct {
	// +kubebuilder:validation:Minimum=1
	ID int32 `json:"id"`
	// +kubebuilder:validation:Format=uuid
	UUID string `json:"uuid"`
}

type AuthentikGroupSpec struct {
	// serverRef is immutable; moving identity ownership requires a new resource.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="serverRef is immutable"
	ServerRef NamespacedName `json:"serverRef"`
	// members is the complete direct membership list, owned by this resource.
	// Users must already exist. No users, credentials or privileges are created.
	// +optional
	// +listType=map
	// +listMapKey=id
	// +kubebuilder:validation:MaxItems=500
	Members []ExistingUserReference `json:"members,omitempty"`
}

type AuthentikGroupStatus struct {
	Ready bool `json:"ready"`
	// +optional
	GroupID string `json:"groupId,omitempty"`
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Group",type=string,JSONPath=`.status.groupId`
type AuthentikGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AuthentikGroupSpec `json:"spec"`
	// +optional
	Status AuthentikGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type AuthentikGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthentikGroup `json:"items"`
}

func init() { SchemeBuilder.Register(&AuthentikGroup{}, &AuthentikGroupList{}) }
