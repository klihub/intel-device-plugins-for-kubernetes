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
	"path/filepath"

	"github.com/intel/intel-device-plugins-for-kubernetes/cmd/cpu_pool_policy/pool"
	"github.com/intel/intel-device-plugins-for-kubernetes/cmd/cpu_pool_policy/statistics"
	"k8s.io/api/core/v1"
	stub "k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/stub"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/topology"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"

	poolapi "github.com/intel/intel-device-plugins-for-kubernetes/pkg/client/clientset/versioned"
	// clientkube "k8s.io/client-go/kubernetes"
	clientrest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	utilnode "k8s.io/kubernetes/pkg/util/node"
)

const (
	PolicyName  = "pool"
	logPrefix   = "[CPU " + PolicyName + " policy] "
	configDir   = "/etc/cpu-pool-plugin-config"
	metricSpace = "default"
)

// plugin executable configuration from the command line/environment variables
type pluginConfig struct {
	ConfigDir    string                   // where to look for CPU pool configuration/ConfigMap
	NodeName     string                   // node name to pick configuration for
	KubeConfig   string                   // kube configuration if not running as a pod
	MetricSpace  string                   // namespace for Metric objects
}

// CPU pool policy
type poolPolicy struct {
	topology        *topology.CPUTopology
	numReservedCPUs int
	pluginCfg       *pluginConfig
	poolCfg         pool.NodeConfig
	pools           *pool.PoolSet
}

// Ensure that poolPolicy implements the CpuPolicy interface.
var _ stub.CpuPolicy = &poolPolicy{}

func NewPoolPolicy(cfg *pluginConfig) stub.CpuPlugin {
	policy := poolPolicy{
		pluginCfg: cfg,
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

	return p.restoreState(s)
}

func (p *poolPolicy) Configure(s stub.State) error {
	logInfo("* Parsing configuration at %s", p.pluginCfg.ConfigDir)
	// read the configuration data from a ConfigMap associated with the pod
	cfg, err := pool.ParseNodeConfig(p.numReservedCPUs, p.pluginCfg.ConfigDir)
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
	s.Delete(containerID)
	p.updateState(s)
}

func getClientSet(kubeConfig string) (*poolapi.Clientset, error) {
	var config *clientrest.Config
	var err error

	if config, err = clientrest.InClusterConfig(); err != nil {
		logWarning("no in-cluster configuration, maybe not running as a pod")
		if kubeConfig == "" {
			return nil, err
		}

		logWarning("trying to load configuration from %s", kubeConfig)
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfig)
	}

	if err != nil {
		return nil, err
	}

	return poolapi.NewForConfig(config)
}

func (p *poolPolicy) restoreState(s stub.State) error {
	// create new statistics object
	clientset, err := getClientSet(p.pluginCfg.KubeConfig)
	if err != nil {
		return err
	}
	stat := statistics.NewStat(p.pluginCfg.NodeName, p.pluginCfg.MetricSpace, clientset)

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

	defaultCPUSet, _ := p.pools.GetPoolCPUSet(pool.DefaultPool)
	s.SetDefaultCPUSet(defaultCPUSet)

	return nil
}

func (p *poolPolicy) validateState(s stub.State) error {
	return nil
}

func getPluginConfig() *pluginConfig {
	cfg := pluginConfig{}

	flag.StringVar(&cfg.ConfigDir, "config", configDir,
		"absolute path to CPU pool plugin configuration directory, expecting ConfigMap-style configuration")
	flag.StringVar(&cfg.NodeName, "node", utilnode.GetHostname(os.Getenv("NODE_NAME")),
		"override node name to pick configuration for")
	flag.StringVar(&cfg.KubeConfig, "kube-config", filepath.Join(os.Getenv("HOME"), ".kube", "config"),
		"override path to kube configuration when not running as a pod")
	flag.StringVar(&cfg.MetricSpace, "metric-namespace", metricSpace,
		"namespace for Metric objects")

	flag.Parse()

	return &cfg
}

func main() {
	cfg := getPluginConfig()
	plugin := NewPoolPolicy(cfg)

	if err := plugin.StartCpuPlugin(); err != nil {
		logPanic("failed to start CPU plugin stub with %s policy: %+v", PolicyName, err)
	}
}
