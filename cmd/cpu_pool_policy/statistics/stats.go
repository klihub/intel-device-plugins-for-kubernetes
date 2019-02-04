/*
Copyright 2018 The Kubernetes Authors.

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

package statistics

import (
	"fmt"

	types "github.com/intel/intel-device-plugins-for-kubernetes/pkg/apis/cpupools.intel.com/v1alpha1"
	poolapi "github.com/intel/intel-device-plugins-for-kubernetes/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
)

type Stat struct {
	nodeName string             // node name
	cs       *poolapi.Clientset // clientset for REST API
	ns       string             // namespace
}

func (s *Stat) String() string {
	if s == nil {
		return ""
	}

	return "name: " + s.nodeName
}

func (s *Stat) UpdatePool(name string, shared, exclusive cpuset.CPUSet, capacity, usage int64) error {

	// first see if the Metric object is already present
	metric, err := s.cs.CpupoolsV1alpha1().Metrics(s.ns).Get(s.nodeName, metav1.GetOptions{})

	if err != nil {
		metric = &types.Metric{
			ObjectMeta: metav1.ObjectMeta{Name: s.nodeName},
		}
		metric, err = s.cs.CpupoolsV1alpha1().Metrics(s.ns).Create(metric)
		if err != nil {
			fmt.Printf("error creating stats: %s", err.Error())
			return err
		}
	}

	var pool types.Pool
	var found bool

	// TODO: make this a map
	for _, pool := range metric.Spec.Pools {
		if pool.PoolName == name {
			found = true
			break
		}
	}
	if !found {
		pool = types.Pool{
			PoolName: name,
		}
	}

	pool.Exclusive = exclusive.String()
	pool.Shared = shared.String()
	pool.Capacity = capacity
	pool.Usage = usage

	if !found {
		metric.Spec.Pools = append(metric.Spec.Pools, pool)
	}

	_, err = s.cs.CpupoolsV1alpha1().Metrics(s.ns).Update(metric)
	if err != nil {
		fmt.Printf("error updating stats: %s", err.Error())
		return err
	}

	return nil
}

func NewStat(nodeName, nameSpace string, cs *poolapi.Clientset) *Stat {
	return &Stat{
		nodeName: nodeName,
		cs:       cs,
		ns:       nameSpace,
	}
}
