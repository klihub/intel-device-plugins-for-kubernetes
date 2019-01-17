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

//
// The pool policy maintains a set of CPU pools to allocate CPU resources to
// containers. The pools are configured externally. Pods request CPU from a
// particular pool explicitly by requesting a corresponding external resource
// unique to the pool, or actually to the set of all pools with the same name
// on different nodes).
//
// There is a number of pre-defined pools which special semantics:
//
//  - ignored:
//    CPUs in this pool are ignored. They can be used outside of kubernetes.
//    Allocations are not allowed from this pool.
//
//  - offline:
//    CPUs in this pool are taken offline (typically to disable hyperthreading
//    for sibling cores). This pool is only used to administer the offline CPUs,
//    allocations are not allowed from this pool.
//
//  - reserved:
//    The reserved pool is the set of CPUs dedicated to system- and kube-
//    reserved pods and other processes.
//
//  - default:
//    Pods which do not request CPU from any particular pool by name are allocated
//    CPU from the default pool. Also, any CPU not assigned to any other pool is
//    automatically assigned to the default pool.
//
// Currently there is no difference in practice between the ignored and offline
// pools, since the actual offlining of CPUs is handled by an external component.
//

package pool

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/intel/intel-device-plugins-for-kubernetes/cmd/cpu_pool_policy/statistics"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	kubeapi "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/topology"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/stub"
)

const (
	logPrefix      = "[cpu-policy/pool] " // log message prefix
	ResourcePrefix = "intel.com/cpupool." // prefix for CPU pool resources
	IgnoredPool    = "ignored"            // CPUs we have to ignore
	OfflinePool    = "offline"            // CPUs which are offline
	ReservedPool   = "reserved"           // CPUs reserved for kube and system
	DefaultPool    = "default"            // CPUs in the default set
)

// A container assigned to run in a pool.
type Container struct {
	id   string        // container ID
	pool string        // assigned pool
	cpus cpuset.CPUSet // exclusive CPUs, if any
	req  int64         // requested milliCPUs
}

// A CPU pool is a set of cores, typically set aside for a class of workloads.
type Pool struct {
	shared cpuset.CPUSet // shared set of CPUs
	pinned cpuset.CPUSet // exclusively allocated CPUs
	used   int64         // total allocations in shared set
	cfg    *Config       // (requested) configuration
}

// All pools available for kube on this node.
type PoolSet struct {
	pools      map[string]*Pool      // all CPU pools
	containers map[string]*Container // container assignments
	topology   *topology.CPUTopology // CPUManager CPU topology info
	sys        *stub.SystemInfo      // system/topology information
	isolated   cpuset.CPUSet         // isolated CPUs
	free       cpuset.CPUSet         // free CPUs
	offline    cpuset.CPUSet         // CPUs taken offline
	reconcile  bool                  // whether needs reconcilation
	stats      *statistics.Stat      // metrics interface
}

// our logger instance
var log = stub.NewLogger(logPrefix)

// Get the CPU pool, request, and limit of a container.
func GetContainerPoolResources(p *v1.Pod, c *v1.Container) (string, int64, int64) {
	var pool string
	var req, lim int64

	if p.ObjectMeta.Namespace == kubeapi.NamespaceSystem {
		pool = ReservedPool
	} else {
		pool = DefaultPool
	}

	if c.Resources.Requests == nil {
		return pool, 0, 0
	}

	for name := range c.Resources.Requests {
		if strings.HasPrefix(name.String(), ResourcePrefix) {
			pool = strings.TrimPrefix(name.String(), ResourcePrefix)
			break
		}
	}

	if res, ok := c.Resources.Requests[v1.ResourceCPU]; ok {
		req = res.MilliValue()
	}

	if res, ok := c.Resources.Limits[v1.ResourceCPU]; ok {
		lim = res.MilliValue()
	}

	return pool, req, lim
}

// Dump a pool as a string.
func (p *Pool) String() string {
	if p == nil {
		return "<nil pool>"
	}

	var shared, pinned string = "-", "-"

	if !p.shared.IsEmpty() {
		shared = "CPU#" + p.shared.String()
	}

	if !p.pinned.IsEmpty() {
		pinned = "CPU#" + p.pinned.String()
	}

	return fmt.Sprintf("<shared: %s, pinned: %s, cfg: %s>", shared, pinned, p.cfg.String())
}

// Create a new CPU pool set with the given configuration.
func NewPoolSet(nc NodeConfig, stats *statistics.Stat) (*PoolSet, error) {
	log.Info("creating new CPU pool set")

	sys, err := stub.DiscoverSystemInfo("")
	if err != nil {
		return nil, err
	}

	ps := &PoolSet{
		pools:      make(map[string]*Pool),
		containers: make(map[string]*Container),
		sys:        sys,
		isolated:   sys.IsolatedCPUSet(),
		stats:      stats,
	}

	if err := ps.Reconfigure(nc); err != nil {
		return nil, err
	}

	return ps, nil
}

// Verify the current pool state.
func (ps *PoolSet) Verify() error {
	required := []string{ReservedPool, DefaultPool}

	for _, name := range required {
		if _, ok := ps.pools[name]; !ok {
			return fmt.Errorf("missing %s pool", name)
		}
	}

	return nil
}

// Get the cpuset of all CPUs and their HT-siblings in the given cpuset.
func hyperthreadCPUSet(sys *stub.SystemInfo, cset *cpuset.CPUSet) cpuset.CPUSet {
	b := cpuset.NewBuilder()
	for _, id := range cset.ToSlice() {
		b.Add(sys.ThreadSiblingCPUSet(id, true).ToSlice()...)
	}
	return b.Result()
}

// Prepare configuration for the reserved pool.
func (ps *PoolSet) prepareReservedPool(cfg NodeConfig) error {
	rc, ok := cfg[ReservedPool]
	if !ok {
		return configError("pool %s: no configuration for required pool", ReservedPool)
	}

	if rc.Cpus != nil && !rc.Cpus.IsEmpty() {
		// check that CPU#0 is in the reserved pool
		if !rc.Cpus.Contains(0) {
			return configError("pool %s: cpu #0 must belong to the reserved pool", ReservedPool)
		}
	} else {
		// set up reserved pool to include CPU#0
		sys  := ps.sys
		cset := cpuset.NewCPUSet()
		ncpu := rc.CpuCount
		for _, id := range sys.CPUSet().ToSlice() {
			tset := sys.ThreadCPUSet(id).Difference(cset)
			if ncpu < tset.Size() {
				cset = cset.Union(cpuset.NewCPUSet(tset.ToSlice()[0:ncpu]...))
				ncpu = 0
			} else {
				cset = cset.Union(tset)
				ncpu -= tset.Size()
			}

			if ncpu == 0 {
				break
			}
		}

		if ncpu > 0 {
			return configError("pool %s: failed to reserve %d CPUs", ReservedPool, ncpu)
		}

		rc.Cpus = &cset
		rc.CpuCount = 0
	}

	return nil
}

// Save the current configuration of all pools.
func (ps *PoolSet) backupConfig() map[string]*Config {
	backup := make(map[string]*Config)
	for pool, p := range ps.pools {
		backup[pool] = p.cfg
	}
	return backup
}

// Restore the configuration of all pools.
func (ps *PoolSet) restoreConfig(backup map[string]*Config) error {
	// restore existing pools (including ones marked for deletion)
	for pool, pc := range backup {
		if p, ok := ps.pools[pool]; !ok {
			return configError("pool %s: cannot restore configuration, pool not found", pool)
		} else {
			p.cfg = pc
		}
	}

	// remove newly added pools
	for pool, _ := range ps.pools {
		if _, ok := backup[pool]; !ok {
			delete(ps.pools, pool)
		}
	}

	return nil
}

// Prepare configuration, check conflicts, collect leftover and offline CPUs.
func (ps *PoolSet) prepareConfig(cfg NodeConfig) error {
	// check/set up the reserved pool, making sure it has CPU#0
	if err := ps.prepareReservedPool(cfg); err != nil {
		return err
	}

	sys  := ps.sys
	isol := ps.isolated
	free := sys.CPUSet().Difference(isol)
	offl := cpuset.NewCPUSet()
	rest := make(map[bool]string)

	//
	// Go through all pools checking
	//   - pool CPUs are available (not taken by other pools)
	//   - pool CPUs match any potential requested isolation
	//   - pool CPUs don't conflict with HT-free pools (CPUs to be taken offline)
	//

	for pool, pc := range cfg {
		if pc.CpuCount == claimLeftover {
			if rest[pc.Isolated] != "" {
				return configError("pool %s: pool %s also claimed leftover CPUs.", pool, rest[pc.Isolated])
			}

			rest[pc.Isolated] = pool

			if _, ok := ps.pools[pool]; !ok {
				ps.pools[pool] = &Pool{}
			}

			continue
		}

		// check that requested CPUs are available
		if pc.Isolated {
			if !pc.Cpus.IsSubsetOf(isol) {
				return configError("pool %s: CPUs #%s not isolated/available", pool, pc.Cpus.Difference(isol))
			}
			isol = isol.Difference(*pc.Cpus)
		} else {
			if !pc.Cpus.IsSubsetOf(free) {
				return configError("pool %s: CPUs #%s not available", pool, pc.Cpus.Difference(free))
			}
			free = free.Difference(*pc.Cpus)
		}

		// check that there is no HT-free/offlining conflict
		if pc.DisableHT {
			off := hyperthreadCPUSet(sys, pc.Cpus)
			if !off.IsSubsetOf(free) {
				return configError("pool %s: CPUs #%s cannot be put offline", pool, off.Difference(free))
			}
			free = free.Difference(off)
			offl = offl.Union(off)
		}

		// update pool configuration, create new pool if needed
		if p, ok := ps.pools[pool]; ok {
			p.cfg = pc
		} else {
			ps.pools[pool] = &Pool{
				shared: pc.Cpus.Clone(),
				pinned: cpuset.NewCPUSet(),
				used:   0,
				cfg:    pc,
			}
		}

		log.Info("prepared pool %s: %s", pool, pc.String())
	}

	ps.offline = offl

	// claim leftover cpus
	for _, pool := range rest {
		if pool == "" {
			continue
		}

		pc := cfg[pool]
		p := ps.pools[pool]

		if pc.Isolated {
			if isol.IsEmpty() {
				return configError("pool %s: no leftover isolated CPUs to claim", pool)
			}
			pc.Cpus = &isol
		} else {
			if free.IsEmpty() {
				return configError("pool %s: no leftover CPUs to claim", pool)
			}
			pc.Cpus = &free
		}
	
		p.cfg = pc

		log.Info("prepared pool %s: using leftover CPUs #%s", pool, pc.Cpus.String())
	}

	// mark deleted pools for removal
	for pool, p := range ps.pools {
		if _, ok := cfg[pool]; ok {
			continue
		}

		if p.used != 0 || !p.pinned.IsEmpty() {
			return configError("pool %s: currently busy, cannot be removed", pool)
		}
	}

	return nil
}

// Check if the pool set is up to date wrt. the configuration.
func (ps *PoolSet) isUptodate() bool {
	for _, p := range ps.pools {
		if !p.isUptodate() {
			return false
		}
	}

	return true
}

// Reconfigure the CPU pool set.
func (ps *PoolSet) Reconfigure(nc NodeConfig) error {
	var err error

	if nc == nil {
		return nil
	}

	// save current configuration
	effective := ps.backupConfig()

	// update configuration, create new pools, mark deletes ones for removal
	if err = ps.prepareConfig(nc); err != nil {
		goto restoreConfig
	}

	// activate the new configuration
	if err = ps.reconcileConfig(); err != nil {
		goto restoreConfig
	}

	// make sure we update pool metrics upon startup
	ps.updateMetrics()

	return nil

restoreConfig:
	ps.restoreConfig(effective)
	return err
}

// Is pool pinned ?
func (p *Pool) isPinned() bool {
	if p.cfg != nil && p.cfg.Cpus != nil {
		return true
	}

	return false
}

// Is pool up-to-date ?
func (p *Pool) isUptodate() bool {
	if p.cfg == nil {
		return false
	}

	return p.cfg.Cpus.Equals(p.shared.Union(p.pinned))
}

// Run one round of reconcilation of the CPU pool set configuration.
func (ps *PoolSet) reconcileConfig() error {
	// check if everything is up-to-date
	if ps.reconcile = !ps.isUptodate(); !ps.reconcile {
		log.Info("pools already up-to-date, nothing to reconcile")
		return nil
	}

	log.Info("CPU pools not up-to-date, reconciling...")

	for pool, p := range ps.pools {
		log.Info("reconciling pool %s (pool %+v, cfg: %+v)", pool, *p, *p.cfg)
		if p.cfg == nil {
			delete(ps.pools, pool)
		} else {
			p.shared = p.cfg.Cpus.Difference(p.pinned)
		}
	}

	return nil
}

// Take up to cnt CPUs from a given CPU set to another.
func (ps *PoolSet) takeCPUs(from, to *cpuset.CPUSet, cnt int) (cpuset.CPUSet, error) {
	return stub.AllocateCpus(from, cnt)
}

// Free up to cnt CPUs from a given CPU set to another.
func (ps *PoolSet) freeCPUs(from, to *cpuset.CPUSet, cnt int) (cpuset.CPUSet, error) {
	if to == nil {
		to = &ps.free
	}

	if cnt > from.Size() {
		cnt = from.Size()
	}

	if cnt == 0 {
		return cpuset.NewCPUSet(), nil
	}

	cset, err := stub.ReleaseCpus(from, cnt)
	if err == nil {
		*to = to.Union(cset)
	}

	return cset, err
}

// Check it the given pool can be allocated CPUs from.
func isAllowedPool(pool string) error {
	if pool == IgnoredPool || pool == OfflinePool {
		return fmt.Errorf("allocation from pool %s is forbidden", pool)
	}
	return nil
}

// Allocate a number of CPUs exclusively from a pool.
func (ps *PoolSet) AllocateCPUs(id string, pool string, numCPUs int) (cpuset.CPUSet, error) {
	if pool == ReservedPool {
		return ps.AllocateCPU(id, pool, int64(numCPUs*1000))
	}

	if pool == "" {
		pool = DefaultPool
	}

	if err := isAllowedPool(pool); err != nil {
		return cpuset.NewCPUSet(), err
	}

	p, ok := ps.pools[pool]
	if !ok {
		return cpuset.NewCPUSet(), fmt.Errorf("non-existent pool %s", pool)
	}

	cpus, err := ps.takeCPUs(&p.shared, &p.pinned, numCPUs)
	if err != nil {
		return cpuset.NewCPUSet(), err
	}
	ps.containers[id] = &Container{
		id:   id,
		pool: pool,
		cpus: cpus,
		req:  int64(cpus.Size()) * 1000,
	}

	ps.updatePoolMetrics(pool)

	log.Info("gave %s/CPU#%s to container %s", pool, cpus.String(), id)

	return cpus.Clone(), nil
}

// Allocate CPU for a container from a pool.
func (ps *PoolSet) AllocateCPU(id string, pool string, req int64) (cpuset.CPUSet, error) {
	if err := isAllowedPool(pool); err != nil {
		return cpuset.NewCPUSet(), nil
	}

	p, ok := ps.pools[pool]
	if !ok {
		return cpuset.NewCPUSet(), fmt.Errorf("pool %s not found", pool)
	}
	ps.containers[id] = &Container{
		id:   id,
		pool: pool,
		cpus: cpuset.NewCPUSet(),
		req:  req,
	}

	p.used += req

	ps.updatePoolMetrics(pool)

	log.Info("gave %dm of %s/CPU#%s to container %s", req, pool,
		p.shared.String(), id)

	return p.shared.Clone(), nil
}

// Return CPU from a container to a pool.
func (ps *PoolSet) ReleaseCPU(id string) {
	c, ok := ps.containers[id]
	if !ok {
		log.Warning("couldn't find allocations for container %s", id)
		return
	}

	delete(ps.containers, id)

	p, ok := ps.pools[c.pool]
	if !ok {
		log.Warning("couldn't find pool %s for container %s", c.pool, id)
		return
	}

	if c.cpus.IsEmpty() {
		p.used -= c.req
		log.Info("cpumanager] released %dm of %s/CPU:%s for container %s", c.req, c.pool, p.shared.String(), c.id)
	} else {
		p.shared = p.shared.Union(c.cpus)
		p.pinned = p.pinned.Difference(c.cpus)

		log.Info("released %s/CPU:%s for container %s", c.pool, p.shared.String(), c.id)
	}

	ps.updatePoolMetrics(c.pool)
	ps.reconcileConfig()
}

// Get the CPU capacity of pools.
func (ps *PoolSet) GetPoolCapacity() v1.ResourceList {
	cap := v1.ResourceList{}

	for pool, p := range ps.pools {
		qty := 1000 * (p.shared.Size() + p.pinned.Size())
		res := v1.ResourceName(ResourcePrefix + pool)
		cap[res] = *resource.NewQuantity(int64(qty), resource.DecimalSI)
	}

	return cap
}

// Get the (shared) CPU sets for pools.
func (ps *PoolSet) GetPoolCPUs() map[string]cpuset.CPUSet {
	cpus := make(map[string]cpuset.CPUSet)

	for pool, p := range ps.pools {
		cpus[pool] = p.shared.Clone()
	}

	return cpus
}

// Get the exclusively allocated CPU sets.
func (ps *PoolSet) GetPoolAssignments(exclusive bool) map[string]cpuset.CPUSet {
	cpus := make(map[string]cpuset.CPUSet)

	for id, c := range ps.containers {
		if exclusive {
			cpus[id] = c.cpus.Clone()
		} else {
			if !c.cpus.IsEmpty() {
				cpus[id] = c.cpus.Clone()
			} else {
				cpus[id], _ = ps.GetPoolCPUSet(c.pool)
			}
		}
	}

	return cpus
}

// Get the CPU allocations for a container.
func (ps *PoolSet) GetContainerCPUSet(id string) (cpuset.CPUSet, bool) {
	c, ok := ps.containers[id]
	if !ok {
		return cpuset.NewCPUSet(), false
	}

	if !c.cpus.IsEmpty() {
		return c.cpus.Clone(), true
	}
	if c.pool == ReservedPool || c.pool == DefaultPool {
		r := ps.pools[ReservedPool]
		d := ps.pools[DefaultPool]
		return r.shared.Union(d.shared), true
	}
	p := ps.pools[c.pool]
	return p.shared.Clone(), true
}

// Get the shared CPUs of a pool.
func (ps *PoolSet) GetPoolCPUSet(pool string) (cpuset.CPUSet, bool) {
	p, ok := ps.pools[pool]
	if !ok {
		return cpuset.NewCPUSet(), false
	}

	if pool == DefaultPool || pool == ReservedPool {
		return ps.pools[DefaultPool].shared.Union(ps.pools[ReservedPool].shared), true
	}
	return p.shared.Clone(), true
}

// Get the exclusive CPU assignments as ContainerCPUAssignments.
func (ps *PoolSet) GetCPUAssignments() map[string]cpuset.CPUSet {
	a := make(map[string]cpuset.CPUSet)

	for _, c := range ps.containers {
		if !c.cpus.IsEmpty() {
			a[c.id] = c.cpus.Clone()
		}
	}

	return a
}

// Get metrics for the given pool.
func (ps *PoolSet) getPoolMetrics(pool string) (string, cpuset.CPUSet, cpuset.CPUSet, int64, int64) {
	if _, ok := ps.pools[pool]; ok && pool != ReservedPool {
		c, s, e := ps.getPoolCPUSets(pool)
		u := ps.getPoolUsage(pool)

		return pool, s, e, c, u
	}

	return "", cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0, 0
}

// Get the shared and exclusive CPUs and the total capacity for the given pool.
func (ps *PoolSet) getPoolCPUSets(pool string) (int64, cpuset.CPUSet, cpuset.CPUSet) {
	var s, e cpuset.CPUSet

	if p, ok := ps.pools[pool]; ok {
		s = p.shared.Clone()
		e = p.pinned.Clone()
	} else {
		s = cpuset.NewCPUSet()
		e = cpuset.NewCPUSet()
	}

	return int64(1000 * (s.Size() + e.Size())), s, e
}

// Get the total CPU allocations for the given pool (in MilliCPUs).
func (ps *PoolSet) getPoolUsage(pool string) int64 {
	p := ps.pools[pool]

	return int64(1000*int64(p.pinned.Size()) + p.used)
}

// Get the total size of a pool (in CPUs).
func (ps *PoolSet) getPoolSize(pool string) int {
	p := ps.pools[pool]

	return p.shared.Size() + p.pinned.Size()
}

// Get the total CPU capacity for the given pool (in MilliCPUs).
func (ps *PoolSet) getPoolCapacity(pool string) int64 {
	p := ps.pools[pool]
	n := p.shared.Size() + p.pinned.Size()

	return int64(1000 * n)
}

// Update metrics for the given pool.
func (ps *PoolSet) updatePoolMetrics(pool string) {
	if name, s, e, c, u := ps.getPoolMetrics(pool); name != "" {
		if err := ps.stats.UpdatePool(name, s, e, c, u); err != nil {
			log.Error("pool metrics update failed: %v", err)
		}
	}
}

// Update all pool metrics.
func (ps *PoolSet) updateMetrics() {
	for pool := range ps.pools {
		ps.updatePoolMetrics(pool)
	}
}

//
// JSON marshalling and unmarshalling
//

// Container JSON marshalling interface
type marshalContainer struct {
	ID   string        `json:"id"`
	Pool string        `json:"pool"`
	Cpus cpuset.CPUSet `json:"cpus"`
	Req  int64         `json:"req"`
}

func (pc Container) MarshalJSON() ([]byte, error) {
	return json.Marshal(marshalContainer{
		ID:   pc.id,
		Pool: pc.pool,
		Cpus: pc.cpus,
		Req:  pc.req,
	})
}

func (pc *Container) UnmarshalJSON(b []byte) error {
	var m marshalContainer

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	pc.id = m.ID
	pc.pool = m.Pool
	pc.cpus = m.Cpus
	pc.req = m.Req

	return nil
}

// Pool JSON marshalling interface
type marshalPool struct {
	Shared cpuset.CPUSet `json:"shared"`
	Pinned cpuset.CPUSet `json:"exclusive"`
	Used   int64         `json:"used"`
	Cfg    *Config       `json:"cfg,omitempty"`
}

func (p Pool) MarshalJSON() ([]byte, error) {
	return json.Marshal(marshalPool{
		Shared: p.shared,
		Pinned: p.pinned,
		Used:   p.used,
		Cfg:    p.cfg,
	})
}

func (p *Pool) UnmarshalJSON(b []byte) error {
	var m marshalPool

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	p.shared = m.Shared
	p.pinned = m.Pinned
	p.used = m.Used
	p.cfg = m.Cfg

	return nil
}

// PoolSet JSON marshalling interface
type marshalPoolSet struct {
	Pools      map[string]*Pool      `json:"pools"`
	Containers map[string]*Container `json:"containers"`
	Reconcile  bool                  `json:"reconcile"`
	Isolated   cpuset.CPUSet         `json:"isolcpus"`
}

func (ps PoolSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(marshalPoolSet{
		Pools:      ps.pools,
		Containers: ps.containers,
		Reconcile:  ps.reconcile,
		Isolated:   ps.isolated,
	})
}

func (ps *PoolSet) UnmarshalJSON(b []byte) error {
	var m marshalPoolSet

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	ps.pools = m.Pools
	ps.containers = m.Containers
	ps.reconcile = m.Reconcile

	if ps.isolated.Equals(m.Isolated) {
		return nil
	}

	return fmt.Errorf("isolated cpuset changed (%s -> %s)",
		m.Isolated.String(), ps.isolated.String())
}
