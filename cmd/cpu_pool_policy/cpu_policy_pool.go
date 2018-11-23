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
	"fmt"
	"flag"
	"os"
	"sync"
	"path/filepath"

	"github.com/intel/intel-device-plugins-for-kubernetes/cmd/cpu_pool_policy/pool"
	metrics "github.com/intel/intel-device-plugins-for-kubernetes/cmd/cpu_pool_policy/statistics"
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
	// PolicyPool is the name of the pool policy
	PolicyPool = "pool"
	// PolicyVendor is the vendor and resource namespace for the pool policy
	PolicyVendor = "intel.com"
	// log message prefix
	logPrefix = "[CPU " + PolicyPool + " policy] "
	// default configuration/ConfigMap directory
	configDir = "/etc/cpu-pool-plugin-config"
	// default namespace for metrics objects
	metricSpace = "default"
	// key for pool policy state in CPUManager checkpointed state
	poolStateKey = "pools"
)

// our logger instance
var log = stub.NewLogger(logPrefix)

// pluginConfig encapsulates configuration supplied to the plugin executable
// It is gathered from the command line and environment variables.
type pluginConfig struct {
	ConfigDir   string        // where to look for configuration/ConfigMap
	NodeName    string        // node name to pick our configuration for
	KubeConfig  string        // .kube directory if not running as a pod
	MetricSpace string        // namespace for metrics objects
}

// poolPolicy implements the 'pool' CPU Manager policy.
type poolPolicy struct {
	sync.Mutex
	topology        *topology.CPUTopology  // CPU topology information
	numReservedCPUs int                    // kube+system-reserved CPUs
	isolatedCPUs    cpuset.CPUSet          // isolated CPUs
	pluginCfg       *pluginConfig          // plugin configuration data
	cfgPicker       stub.ConfigPicker      // node configuration picker
	poolCfg         pool.NodeConfig        // CPU pool configuration
	pools           *pool.PoolSet          // CPU pools
}

// Ensure that poolPolicy implements the CpuPolicy interface.
var _ stub.CpuPolicy = &poolPolicy{}

func initPoolPolicy(cfg *pluginConfig) (*poolPolicy, error) {
	p := &poolPolicy{pluginCfg:cfg}

	if err := p.watchConfig(); err != nil {
		return nil, err
	}

	return p, nil
}

// NewPoolPolicy creates a CPU plugin stub, initialized with the pool policy.
func NewPoolPolicy(cfg *pluginConfig) stub.CpuPlugin {
	log.Info("creating '%s' policy plugin", PolicyPool)

	policy, err := initPoolPolicy(cfg)
	if err != nil {
		log.Error("failed to initialize poolPolicy instance: %v", err)
		return nil
	}
	if plugin, err := stub.NewCpuPlugin(policy, PolicyVendor); err != nil {
		log.Error("failed to create CPU policy stub with '%s' policy: %v", PolicyPool, err)
		return nil
	} else {
		return plugin
	}
}

// Name returns the well-known policy name for the pool policy.
func (p *poolPolicy) Name() string {
	return string(PolicyPool)
}

// NewPolicy is the 'constructor', called when the policy gets registered with the CPUManager.
func (p *poolPolicy) NewPolicy(topology *topology.CPUTopology, numReservedCPUs int) error {
	var kcl stub.KernelCmdline

	isolated, err := kcl.IsolatedCPUSet()
	if err != nil {
		return err
	}

	p.topology = topology
	p.numReservedCPUs = numReservedCPUs
	p.isolatedCPUs = isolated

	return nil
}

// Start prepares the pool policy for accepting CPUManager container requests.
func (p *poolPolicy) Start(s stub.State) error {
	log.Info("starting '%s' policy plugin", PolicyPool)

	if err := p.validateState(s); err != nil {
		return err
	}

	if err := p.createPools(); err != nil {
		return err
	}

	if err := p.restoreState(s); err != nil {
		return err
	}

	if err := p.configure(); err != nil {
		return err
	}

	if err := p.updateState(s); err != nil {
		return err
	}

	return nil
}

// Allocate resources for the given container.
func (p *poolPolicy) AddContainer(s stub.State, pod *v1.Pod, container *v1.Container, containerID string) error {
	var cset cpuset.CPUSet
	var err error

	p.Lock()
	defer p.Unlock()

	if _, ok := p.pools.GetContainerCPUSet(containerID); ok {
		log.Info("container %s already has allocations, nothing to do", containerID)
		return nil
	}

	pool, req, lim := pool.GetContainerPoolResources(pod, container)

	if req != 0 {
		if req == lim && req % 1000 == 0 {
			cset, err = p.pools.AllocateCPUs(containerID, pool, int(req / 1000))
		} else {
			cset, err = p.pools.AllocateCPU(containerID, pool, req)
		}
	} else {
		cset, err = p.pools.AllocateCPU(containerID, pool, req)
	}

	if err != nil {
		log.Error("pool %s: failed to add container %s (request %d - %d): %v",
			pool, containerID, req, lim, err)
		return err
	}

	log.Info("pool %s: added %s (request %d - %d) => CPUs %s", pool, containerID, req, lim, cset.String())

	p.updateState(s)

	return nil
}

// Release resources of the given container.
func (p *poolPolicy) RemoveContainer(s stub.State, containerID string) {
	p.Lock()
	defer p.Unlock()

	p.pools.ReleaseCPU(containerID)
	s.Delete(containerID)

	p.updateState(s)
}

// Restore pool state from the last checkpointed state.
func (p *poolPolicy) restoreState(s stub.State) error {
	log.Info("restoring last checkpointed '%s' policy state", PolicyPool)

	if poolState, ok := s.GetPolicyEntry(poolStateKey); ok {
		if err := p.pools.UnmarshalJSON([]byte(poolState)); err != nil {
			return err
		}
	}

	assignments := p.pools.GetPoolAssignments(false)
	for id, _ := range assignments {
		log.Info("checking container %s", id)
		if _, found := s.GetCPUSet(id); !found {
			log.Info("releasing CPU for lingering container %s", id)
			p.pools.ReleaseCPU(id)
		}
	}

	return nil
}

// Validate the state supplied to the pool policy.
func (p *poolPolicy) validateState(s stub.State) error {
	// TODO: add basic sanity checks.
	return nil
}

// Update the pool/policy state to reflect the latest changes in allocations.
func (p *poolPolicy) updateState(s stub.State) error {
	if p.pools == nil {
		return nil
	}

	// update private, policy-specific state
	poolState, err := p.pools.MarshalJSON()
	if err != nil {
		return err
	}
	s.SetPolicyEntry(poolStateKey, string(poolState))

	// update container CPU assignments
	assignments := p.pools.GetPoolAssignments(false)
	for id, cset := range assignments {
		s.SetCPUSet(id, cset)
	}

	// update resource capacity declarations
	resources := p.pools.GetPoolCapacity()
	for name, qty := range resources {
		s.UpdateResource(name, qty)
	}

	// update default CPUSet
	defaultCPUSet, _ := p.pools.GetPoolCPUSet(pool.DefaultPool)
	s.SetDefaultCPUSet(defaultCPUSet)

	return nil
}

// Reconfigure the pools using the currently active configuration.
func (p *poolPolicy) configure() error {
	log.Info("configuring CPU pools from %s", p.pluginCfg.ConfigDir)

	path, err := p.pickConfig()
	if err != nil {
		log.Error("couldn't find configuration for node %s (%v)", p.pluginCfg.ConfigDir, err)
	} else {
		log.Info("configuration for node %s: %s", p.pluginCfg.NodeName, path)
	}

	if cfg, err := pool.ParseNodeConfig(p.numReservedCPUs, path); err != nil {
		return err
	} else {
		p.poolCfg = cfg
	}

	log.Info("CPU pool configuration: %s", p.poolCfg.String())

	p.Lock()
	defer p.Unlock()
	if err := p.pools.Reconfigure(p.poolCfg); err != nil {
		return err
	}

	return nil
}

// Set up node configuration picker/monitoring.
func (p *poolPolicy) watchConfig() error {
	if p.cfgPicker != nil {
		return nil
	}

	picker := stub.NewConfigPicker(p.pluginCfg.ConfigDir)
	notify := func () {
		log.Info("CPU pool configuration has changed...")
		p.configure()
	}
	if err := picker.WatchConfig(notify); err != nil {
		return err
	}

	p.cfgPicker = picker
	return nil
}

// Pick our configuration file.
func (p *poolPolicy) pickConfig() (string, error) {
	return p.cfgPicker.PickConfig(p.pluginCfg.NodeName)
}

// Create and initialize a(n empty) pool set.
func (p *poolPolicy) createPools() error {
	log.Info("initializing CPU pools")

	metrics, err := p.createMetricsApi()
	if err != nil {
		return err
	}

	p.pools, err = pool.NewPoolSet(nil, p.isolatedCPUs, metrics)
	if err != nil {
		return err
	}
	p.pools.SetAllocator(TakeByTopology, p.topology)

	return nil
}

// Create the pool metrics API interface.
func (p *poolPolicy) createMetricsApi() (*metrics.Stat, error) {
	var config *clientrest.Config
	var client *poolapi.Clientset
	var err error

	log.Info("initializing pool metrics interface")

	if config, err = clientrest.InClusterConfig(); err != nil {
		log.Warning("no in-cluster configuration, maybe not running as a pod")

		if p.pluginCfg.KubeConfig == "" {
			return nil, err
		}

		log.Warning("retrying with configuration from %s", p.pluginCfg.KubeConfig)

		if config, err = clientcmd.BuildConfigFromFlags("", p.pluginCfg.KubeConfig); err != nil {
			return nil, err
		}
	}

	if client, err = poolapi.NewForConfig(config); err != nil {
		return nil, err
	}

	return metrics.NewStat(p.pluginCfg.NodeName, p.pluginCfg.MetricSpace, client), nil
}

// Parse the command line for configuration options.
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

// Start up the pool CPU policy.
func main() {
	cfg := getPluginConfig()
	plugin := NewPoolPolicy(cfg)

	sys, err := stub.DiscoverSystemInfo("")
	if err != nil {
		fmt.Printf("failed to discover system info: %+v\n", err)
	} else {
		fmt.Printf("SystemInfo:\n")
		for _, pkg := range sys.Packages {
			fmt.Printf("  package: %+v\n", *pkg)
		}
		for _, node := range sys.Nodes {
			fmt.Printf("  node: %+v\n", *node)
		}
		for _, cpu := range sys.Cpus() {
			fmt.Printf("  cpu: %+v\n", *cpu)
		}
	}

	if err := plugin.SetupAndServe(); err != nil {
		log.Fatal("failed to start pool CPU policy plugin: %s", err.Error())
	}

}
