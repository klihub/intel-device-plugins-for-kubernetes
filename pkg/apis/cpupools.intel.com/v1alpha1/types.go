package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type Pool struct {
	PoolName  string `json:"poolName"`
	Usage     int    `json:"usage"`
	Capacity  int    `json:"capacity"`
	Exclusive string `json:"exclusive"`
	Shared    string `json:"shared"`
}

type MetricSpec struct {
	Pools []Pool `json:"pools"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Metric struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec MetricSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type MetricList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Metrics []Metric `json:"metrics"`
}
