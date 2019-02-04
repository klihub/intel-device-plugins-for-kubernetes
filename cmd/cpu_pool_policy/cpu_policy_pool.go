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

package main

import (
	"flag"
	"os"

	"github.com/intel/intel-device-plugins-for-kubernetes/cmd/cpu_pool_policy/pool"
	"github.com/intel/intel-device-plugins-for-kubernetes/cmd/cpu_pool_policy/statistics"
	"k8s.io/api/core/v1"
	stub "k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/stub"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/topology"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"

	poolapi "github.com/intel/intel-device-plugins-for-kubernetes/pkg/client/clientset/versioned"
	// clientkube "k8s.io/client-go/kubernetes"
	clientrest "k8s.io/client-go/rest"
	utilnode "k8s.io/kubernetes/pkg/util/node"
)

const (
	PolicyName = "pool"
	logPrefix  = "[" + PolicyName + " CPU policy] "
	configDir  = "/etc/cpu-pool-plugin-config"
)

type poolPolicy struct {
	topology        *topology.CPUTopology
	numReservedCPUs int
	cfg             map[string]string
	poolCfg         pool.NodeConfig
	pools           *pool.PoolSet
	configPath      string
	nodeName        string
	nameSpace       string
	cs              *poolapi.Clientset
}

// Ensure that poolPolicy implements the CpuPolicy interface.
var _ stub.CpuPolicy = &poolPolicy{}

func NewPoolPolicy(configPath, nodeName, nameSpace string) stub.CpuPlugin {
	policy := poolPolicy{
		configPath: configPath,
		nodeName:   nodeName,
		nameSpace:  nameSpace,
	}
	plugin, err := stub.NewCpuPlugin(&policy, "intel.com")
	if err != nil {
		logPanic("failed to create CPU plugin stub for %s policy: %+v", PolicyName, err)
	}

	return plugin
}

func (p *poolPolicy) Name() string {
	return string(PolicyName)
}

func (p *poolPolicy) Start(s stub.State, topology *topology.CPUTopology, numReservedCPUs int) error {
	p.topology = topology
	p.numReservedCPUs = numReservedCPUs

	conf, err := clientrest.InClusterConfig()
	if err != nil {
		return err
	}

	p.cs, err = poolapi.NewForConfig(conf)
	if err != nil {
		return err
	}

	if err := p.restoreState(s); err != nil {
		return err
	}

	return nil
}

func (p *poolPolicy) Configure(s stub.State) error {
	logInfo("* Parsing configuration at %s", p.configPath)
	// read the configuration data from a ConfigMap associated with the pod
	cfg, err := pool.ParseNodeConfig(p.numReservedCPUs, p.configPath)
	if err != nil {
		return err
	}

	logInfo("Configuration: %s", cfg.String())

	p.poolCfg = cfg

	if err := p.pools.Reconfigure(p.poolCfg); err != nil {
		logError("failed to reconfigure pools: %s", err.Error())
		return err
	}

	p.updateState(s)

	return nil
}

func (p *poolPolicy) restoreState(s stub.State) error {

	// create new statistics object

	stat := statistics.NewStat(p.nodeName, p.nameSpace, p.cs)

	p.pools, _ = pool.NewPoolSet(nil, stat)
	p.pools.SetAllocator(TakeByTopology, p.topology)

	if poolState, ok := s.GetPolicyEntry("pools"); ok {
		if err := p.pools.UnmarshalJSON([]byte(poolState)); err != nil {
			return err
		}
	}

	return nil
}

func (p *poolPolicy) updateState(s stub.State) error {
	if p.pools == nil {
		return nil
	}

	poolState, err := p.pools.MarshalJSON()
	if err != nil {
		return err
	}

	s.SetPolicyEntry("pools", string(poolState))

	assignments := p.pools.GetPoolAssignments(false)
	for id, cset := range assignments {
		s.SetCPUSet(id, cset)
	}

	resources := p.pools.GetPoolCapacity()
	for name, qty := range resources {
		s.UpdateResource(name, qty)
	}

	return nil
}

func (p *poolPolicy) validateState(s stub.State) error {
	return nil
}

func (p *poolPolicy) AddContainer(s stub.State, pod *v1.Pod, container *v1.Container, containerID string) error {
	var err error
	var cset cpuset.CPUSet

	logInfo("AddContainer")

	if _, ok := p.pools.GetContainerCPUSet(containerID); ok {
		logInfo("container already present in state, skipping (container id: %s)", containerID)
		return nil
	}

	pool, req, lim := pool.GetContainerPoolResources(pod, container)

	logInfo("container %s asks for %d/%d from pool %s", containerID, req, lim, pool)

	if req != 0 && req == lim && req%1000 == 0 {
		cset, err = p.pools.AllocateCPUs(containerID, pool, int(req/1000))
	} else {
		cset, err = p.pools.AllocateCPU(containerID, pool, req)
	}

	if err != nil {
		logError("unable to allocate CPUs (container id: %s, error: %v)", containerID, err)
		return err
	}

	logInfo("allocated CPUSet: %s", cset.String())
	p.updateState(s)

	return nil
}

func (p *poolPolicy) RemoveContainer(s stub.State, containerID string) {
	logInfo("RemoveContainer")

	p.pools.ReleaseCPU(containerID)
	p.updateState(s)
}

func main() {
	var configPath string
	var nameSpace string

	flag.StringVar(&configPath, "config", configDir, "absolute path to CPU pool plugin configuration directory, expecting ConfigMap-style configuration")
	flag.StringVar(&nameSpace, "namespace", "default", "namespace for Metric objects")
	flag.Parse()

	// if NODE_NAME is not set then try to use hostname
	nodeName := utilnode.GetHostname(os.Getenv("NODE_NAME"))

	plugin := NewPoolPolicy(configPath, nodeName, nameSpace)

	if err := plugin.StartCpuPlugin(); err != nil {
		logPanic("failed to start CPU plugin stub with static policy: %+v", err)
	}
}
