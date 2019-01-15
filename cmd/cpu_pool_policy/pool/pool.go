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
/*
	"io/ioutil"
*/
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
/*
	wildcardCPU    = "*"                  // wildcard for claiming leftover CPUs
	claimLeftover  = -1                   // pool size used for '*'
*/
)

/*
// Node pool configuration in the filesystem.
type configFile map[string]configFileEntry

// A single pool entry in the configuration file.
type configFileEntry struct {
	CpuCount  int    `json:"cpucount,omitempty"`  // size, if cpus auto-picked
	Cpus      string `json:"cpus,omitempty"`      // cpus, if explicitly set
	Isolate   bool   `json:"isolate,omitempty"`   // use isolated CPUs
	DisableHT bool   `json:"disableHT,omitempty"` // take HT siblings offline
}

// Runtime configuration for a single CPU pool.
type Config struct {
	Size       int           `json:"size"`                // number of CPUs to allocate
	Cpus      *cpuset.CPUSet `json:"cpus,omitempty"`      // explicit CPUs to allocate, if given
	Isolate    bool          `json:"isolate,omitempty"`   // use isolated CPUs
	DisableHT  bool          `json:"disableHT,omitempty"` // take HT siblings offline
}

// Node CPU pool configuration.
type NodeConfig map[string]*Config
*/

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
	containers map[string]*Container // containers assignments
	topology   *topology.CPUTopology // CPU topology info
	sys        *stub.SystemInfo      // system/topology information
	isolated   cpuset.CPUSet         // isolated CPUs
	free       cpuset.CPUSet         // free CPUs
	reconcile  bool                  // whether needs reconcilation
	stats      *statistics.Stat      // metrics interface
}

// our logger instance
var log = stub.NewLogger(logPrefix)

/*
// Create default node CPU pool configuration.
func DefaultNodeConfig(numReservedCPUs int) (NodeConfig, error) {
	nc := make(NodeConfig)

	if err := nc.setCPUCount(ReservedPool, numReservedCPUs); err != nil {
		return NodeConfig{}, err
	}

	if err := nc.claimLeftoverCpus(DefaultPool); err != nil {
		return NodeConfig{}, err
	}

	return nc, nil
}

// Parse node CPU pool configuration.
func ParseNodeConfig(path string, numReservedCPUs int) (NodeConfig, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return NodeConfig{}, fmt.Errorf("failed to parse configuration: %v", err)
	}

	file := make(configFile)
	if err = json.Unmarshal(buf, &file); err != nil {
		return NodeConfig{}, fmt.Errorf("failed to parse configuration: %v", err)
	}

	nc := make(NodeConfig)
	for pool, cfg := range file {
		if err := nc.setPoolConfig(pool, cfg); err != nil {
			return NodeConfig{}, err
		}
	}

	reservedConfig := configFileEntry{CpuCount: numReservedCPUs}
	if err := nc.setPoolConfig(ReservedPool, reservedConfig); err != nil {
		return NodeConfig{}, err
	}

	return nc, nil
}

// Dump node CPU pool configuration as string.
func (nc NodeConfig) String() string {
	if nc == nil {
		return "{}"
	}

	str := "{ "
	for pool, cfg := range nc {
		str += fmt.Sprintf("%s: %s, ", pool, cfg.String())
	}
	str += "}"

	return str
}

// Configure the given pool with the given configuration.
func (nc NodeConfig) setPoolConfig(pool string, cfg configFileEntry) error {
	if cfg.CpuCount != 0 && cfg.Cpus != "" {
		return configError("pool %s has both size (%d) and cpus (%s) set", pool, cfg.CpuCount, cfg.Cpus)
	}

	if pool == IgnoredPool || pool == OfflinePool {
		if cfg.Cpus == "" {
			return configError("pool %s must be configured with explicit cpus", pool)
		}

		if cfg.Isolate || cfg.DisableHT {
			return configError("pool %s can't be isolated or HT-disabled", pool)
		}
	}

	c := &Config{
		Isolate:   cfg.Isolate,
		DisableHT: cfg.DisableHT,
		Size:      cfg.CpuCount,
	}
	nc[pool] = c

	if cfg.Cpus != "" {
		if cfg.Cpus != wildcardCPU {
			cpus, err := cpuset.Parse(cfg.Cpus)
			if err != nil {
				return configError("pool %s has invalid cpus (%s)", pool, cfg.Cpus)
			}
			c.Cpus = &cpus
		} else {
			c.Size = claimLeftover
		}
	}

	return nil
}

// Configure the given pool with a given number of CPUs.
func (nc NodeConfig) setCPUCount(pool string, cnt int) error {
	if c, ok := nc[pool]; !ok {
		nc[pool] = &Config{
			Size: cnt,
		}
	} else {
		if c.Cpus != nil && c.Cpus.Size() != cnt {
			return configError("pool %s wants cpus %s but cpu count %d", pool, c.Cpus, cnt)
		}
	}

	return nil
}

// Configure the given pool for claiming any leftover/unused CPUs.
func (nc NodeConfig) claimLeftoverCpus(pool string) error {
	if pool == IgnoredPool || pool == OfflinePool {
		return configError("pool %s cannot be configured with leftover CPUs", pool)
	}

	for wcp, cfg := range nc {
		if cfg.CpuCount == claimLeftover && wcp != pool {
			return configError("multiple wildcard pools: %s, %s", wcp, pool)
		}
	}

	nc[pool] = &Config{
		Size: claimLeftover,
	}

	return nil
}

// Create a formatted configuration error.
func configError(format string, args ...interface{}) error {
	return fmt.Errorf("configuration error:" + format, args...)
}

// Dump a configuration as a string.
func (cfg *Config) String() string {
	if cfg == nil {
		return "<to be removed>"
	}

	if cfg.Cpus != nil {
		return fmt.Sprintf("<CPU#%s>", cfg.Cpus.String())
	}

	return fmt.Sprintf("<any %d CPUs>", cfg.CpuCount)
}
*/

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

	kcl, err := stub.GetKernelCmdline()
	if err != nil {
		return nil, err
	}
	isolated, err := kcl.IsolatedCPUSet()
	if err != nil {
		return nil, err
	}


	ps := &PoolSet{
		pools:      make(map[string]*Pool),
		containers: make(map[string]*Container),
		sys:        sys,
		isolated:   isolated,
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

// Check the given configuration for obvious errors.
func (ps *PoolSet) checkConfig(nc NodeConfig) error {
	//
	// Go through all configured pools, checking that
	//  - each pool is configured either by cpus or by cpu count
	//  - max. one pool is configured to claim leftover cpus
	//  - no cpu is explicitly assigned to multiple pools
	//  - explicit cpus for isolated pools are isolated
	//  - there are enough cpus for all pools
	//  - there are enough isolated cpus
	//
	// TODO: we should also check for these, but ATM we don't
	//  - conflicts between explicit cpus and HT-free pools
	//

	isolated  := ps.isolated
	regular   := ps.sys.CPUSet().Difference(isolated)
	explicit  := cpuset.NewCPUSet()
	cpucount  := 0
	isolcount := 0
	leftover := ""

	for pool, cfg := range nc {
		// pool configured either by explicit cpus or by cpu count
		if cfg.Cpus != nil && cfg.CpuCount != 0 {
			return configError("pool %s has both size (%d) and cpus (%s) set", pool, cfg.CpuCount, cfg.Cpus)
		} else {
			if cfg.Cpus == nil && cfg.CpuCount == 0 {
				return configError("pool %s has neither cpu count nor cpus set", pool)
			}
		}

		// max. one pool is configured to claim leftover cpus
		if cfg.CpuCount == claimLeftover {
			if leftover != "" {
				configError("both pools %s and %s want to claim leftover cpus", leftover, pool)
			}
			leftover = pool
			continue
		}

		// no cpu is explicitly assigned to multiple pools
		if cfg.Cpus != nil {
			taken := cfg.Cpus.Intersection(explicit)
			if taken.Size() != 0 {
				return configError("pool %s: cpus %s also assigned to another pool", pool, taken)
			}
			explicit = cfg.Cpus.Union(explicit)

			// explicit cpus for isolated pools are isolated
			if cfg.Isolate {
				missing := cfg.Cpus.Intersection(isolated)
				if missing.Size() != 0 {
					return configError("pool %s: of requested cpus %s are not isolated", missing)
				}
				isolcount += cfg.Cpus.Size()
			} else {
				cpucount += cfg.Cpus.Size()
			}
		} else {
			if cfg.Isolate {
				isolcount += cfg.CpuCount
			} else {
				cpucount += cfg.CpuCount
			}
		}
	}

	if cpucount > regular.Size() {
		return configError("not enough cpus for all pools (%d < %d)", cpucount, regular.Size())
	}

	if isolcount > isolated.Size() {
		return configError("not enough isolated cpus (%d > %d)", isolcount, isolated.Size())
	}

	extra := regular.Size() - cpucount

	if leftover != "" {
		if extra == 0 {
			return configError("pool %s: no leftover cpus to claim", leftover)
		}
		nc[leftover].CpuCount = extra
	} else {
		def := nc[DefaultPool]
		if extra == 0 {
			if def == nil {
				return configError("pool %s: no leftover cpus to claim", DefaultPool)
			}
		} else {
			log.Info("pool %s: will claim %d leftover cpus", DefaultPool, extra)
			if def == nil {
				nc[DefaultPool] = &Config{CpuCount: extra}
			}
		}
	}

/*
	allCPUs := ps.sys.OnlineCPUSet().Difference(ps.isolated)
	numCPUs := allCPUs.Size()
	leftover := ""

	for name, c := range nc {
		if c.Size < 0 {
			leftover = name
			continue
		}

		if c.Size > numCPUs {
			return fmt.Errorf("not enough CPU (%d) left for pool %s (%d)",
				numCPUs, name, c.Size)
		}

		numCPUs -= c.Size
	}

	if leftover != "" {
		nc[leftover] = &Config{
			Size: numCPUs,
		}
	} else {
		if _, ok := cfg[DefaultPool]; !ok {
			nc[DefaultPool] = &Config{
				Size: numCPUs,
			}
		}
	}
*/

	return nil
}

// Create new pools, update configuration of existing ones, mark purged ones for removal.
func (ps *PoolSet) updateConfig(nc NodeConfig) {
	// create new pools, update configuration of existing ones
	for pool, cfg := range nc {
		if p, ok := ps.pools[pool]; !ok {
			ps.pools[pool] = &Pool{
				shared: cpuset.NewCPUSet(),
				pinned: cpuset.NewCPUSet(),
				cfg:    cfg,
			}
			log.Info("pool %s: added with configuration %s", pool, cfg.String())
		} else {
			p.cfg = cfg
			log.Info("pool %s: updated configuration: %s", pool, cfg.String())
		}

	}

	// mark purged pools for removal
	for pool, p := range ps.pools {
		if pool == ReservedPool || pool == DefaultPool {
			continue
		}
		if _, ok := nc[pool]; !ok {
			p.cfg = nil
			log.Info("pool %s: marked for removal", pool)
		}
	}
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
	if nc == nil {
		return nil
	}

	if err := ps.checkConfig(nc); err != nil {
		return err
	}

	// update pools config, create new ones, mark purged ones for removal
	ps.updateConfig(nc)

	// trigger reconcilation
	if err := ps.reconcileConfig(); err != nil {
		return err
	}

	// make sure we update pool metrics upon startup
	ps.updateMetrics()
	return nil
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

	//
	// TODO:
	//   Only an oversized *default* pool should be considered up-to-date.
	//   Others should be considered up-to-date only for an exact match.
	//
	//   Since the pool currently does not know its own name, we cannot
	//   test for defaultness here, hence the overly permissive check.
	//   In principle this should not break things (too) badly. For each
	//   oversized non-default pool there should be at least one undersized
	//   pool (lacking extra CPUs in the oversized one) which will prevent
	//   the full PoolSet from becoming up-to-date.

	// TODO: should be IsSubsetOf for default, Equals for other pools
	if p.cfg.Cpus != nil {
		return p.cfg.Cpus.IsSubsetOf(p.shared.Union(p.pinned))

	}

	// TODO: should be <= for default, == for all other pools
	if p.cfg.CpuCount <= p.shared.Union(p.pinned).Size() {
		return true
	}

	return false
}

// Calculate the shrinkable capacity of a pool.
func (ps *PoolSet) freeCapacity(pool string) int {
	p, ok := ps.pools[pool]
	if ok {
		return 1000*p.shared.Size() - int(p.used)
	}
	return 0
}

// Is the given pool marked for removal ?
func (ps *PoolSet) isRemoved(pool string) bool {
	p, ok := ps.pools[pool]
	if !ok {
		return false
	}
	return p.cfg == nil
}

// Is the given pool idle ?
func (ps *PoolSet) isIdle(pool string) bool {
	p, ok := ps.pools[pool]
	if !ok {
		return false
	}
	return p.used == 0 && p.pinned.IsEmpty()
}

// Remove the given (assumed to be idle) pool.
func (ps *PoolSet) removePool(pool string) {
	if p, ok := ps.pools[pool]; ok {
		ps.free = ps.free.Union(p.shared)
		delete(ps.pools, pool)
	}
}

// Shrink a pool to its minimum possible size.
func (ps *PoolSet) trimPool(pool string) bool {
	free := ps.freeCapacity(pool) / 1000
	if free < 1 {
		return false
	}

	p, _ := ps.pools[pool]
	if _, err := ps.freeCPUs(&p.shared, &ps.free, free); err != nil {
		log.Warning("failed to shrink pool %s by %d CPUs", pool, free)
		return false
	}

	log.Info("pool %s: trimmed by %d CPUs", pool, free)

	return true
}

// Trim pools, also removing unused idle ones.
func (ps *PoolSet) trimPools() {
	for pool := range ps.pools {
		if ps.isRemoved(pool) && ps.isIdle(pool) {
			ps.removePool(pool)
		} else {
			ps.trimPool(pool)
		}
	}
}

// Allocate reserved pool.
func (ps *PoolSet) allocateReservedPool() {
	r := ps.pools[ReservedPool]

	if r.cfg.Cpus != nil && !r.cfg.Cpus.Intersection(ps.free).IsEmpty() {
		cset := r.cfg.Cpus.Intersection(ps.free)
		ps.free = ps.free.Difference(cset).Union(r.shared)
		r.shared = cset
	}

	if more := r.cfg.CpuCount - r.shared.Size(); more > 0 {
		ps.takeCPUs(&ps.free, &r.shared, more)
	}

	log.Info("pool %s: allocated CPU#%s (%d)", ReservedPool,
		r.shared.String(), r.shared.Size())

	if r.shared.Size() < r.cfg.CpuCount {
		log.Error("pool %s: insufficient cpus %s (need %d)", ReservedPool,
			r.shared.String(), r.cfg.CpuCount)
	}
}

// Allocate pools specified by explicit CPU ids.
func (ps *PoolSet) allocateByCPUId() {
	for pool, p := range ps.pools {
		if ps.isRemoved(pool) {
			continue
		}

		if !p.isPinned() || p.isUptodate() {
			continue
		}

		if cpus := p.cfg.Cpus.Intersection(ps.free); !cpus.IsEmpty() {
			p.shared = p.shared.Union(cpus)
			ps.free = ps.free.Difference(cpus)

			log.Info("pool %s: allocated requested CPU#%s (%d)", pool,
				cpus.String(), cpus.Size())
		}
	}
}

// Allocate pools specified by size.
func (ps *PoolSet) allocateByCPUCount() {
	for pool, p := range ps.pools {
		if ps.isRemoved(pool) {
			continue
		}

		if p.isPinned() || p.isUptodate() {
			continue
		}

		cnt := p.cfg.CpuCount - (p.shared.Size() + p.pinned.Size())
		cpus, _ := ps.takeCPUs(&ps.free, &p.shared, cnt)

		log.Info("pool %s: allocated available CPU#%s (%d)", pool,
			cpus.String(), cpus.Size())
	}
}

// Allocate any remaining unused CPUs to the given pool.
func (ps *PoolSet) claimLeftoverCPUs(pool string) {
	p, ok := ps.pools[pool]
	if !ok || ps.free.IsEmpty() {
		return
	}
	p.shared = p.shared.Union(ps.free)
	log.Info("pool %s: claimed leftover CPU#%s (%d)", pool,
		ps.free.String(), ps.free.Size())
	ps.free = cpuset.NewCPUSet()
}

// Get the full set of CPUs in the pool set.
func (ps *PoolSet) getFreeCPUs() {
	ps.free = ps.sys.CPUSet().Difference(ps.isolated)
	for _, p := range ps.pools {
		ps.free = ps.free.Difference(p.shared.Union(p.pinned))
	}
}

// Run one round of reconcilation of the CPU pool set configuration.
func (ps *PoolSet) reconcileConfig() error {
	// check if everything is up-to-date
	if ps.reconcile = !ps.isUptodate(); !ps.reconcile {
		log.Info("pools already up-to-date, nothing to reconcile")
		return nil
	}

	log.Info("CPU pools not up-to-date, reconciling...")

	//
	// Our pool reconcilation algorithm is:
	//
	//   1. update list of free CPUs
	//   2. trim pools (removing unused idle ones)
	//   3. allocate the reserved pool
	//   4. allocate pools configured with specific CPUs
	//   5. allocate pools configured by total CPU count
	//   6. slam any remaining CPUs to the default pool
	//
	// Check the pool allocations vs. configuration and if
	// everything adds up, mark the pool set as reconciled.
	// Update pool metrics at the same time.
	//

	ps.getFreeCPUs()

	ps.trimPools()
	ps.allocateReservedPool()
	ps.allocateByCPUId()
	ps.allocateByCPUCount()
	ps.claimLeftoverCPUs(DefaultPool)

	ps.reconcile = false
	for pool, p := range ps.pools {
		ps.updatePoolMetrics(pool)
		if !p.isUptodate() {
			ps.reconcile = true
		}

		log.Info("pool %s: %s", pool, p.String())
	}

	if !ps.reconcile {
		log.Info("CPU pools are now up-to-date")
	} else {
		log.Info("CPU pools need further reconcilation...")
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
