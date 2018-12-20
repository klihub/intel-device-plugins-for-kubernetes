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

package stub

import (
	"fmt"
	"sort"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
)

const (
	PreferFullCores = 1 << iota    // allocate idle cores first
	PreferFullNodes                // allocate idle NUMA nodes first
	PreferFullPackages             // allocate idle physical packages first

	PreferFullSockets = PreferFullPackages
)

// Physical packages in the system.
type packages struct {
	idle []*PackageInfo            // fully idle packages
	used []*PackageInfo            // partially allocated packages
	full []*PackageInfo            // fully allocated packages
	pick []*PackageInfo            // packages being picked/sorted
	iset cpuset.CPUSet             // .idle as CPUSet
	uset cpuset.CPUSet             // .used as CPUSet
	fset cpuset.CPUSet             // .full as CPUSet
	sort.Interface
	lessfn func ([]*PackageInfo, int, int) bool
}

// NUMA nodes in the system.
type nodes struct {
	idle []*NodeInfo               // fully idle nodes
	used []*NodeInfo               // partially allocated nodes
	full []*NodeInfo               // fully allocated nodes
	pick []*NodeInfo               // nodes being picked/sorted
	iset cpuset.CPUSet             // .idle as CPUSet
	uset cpuset.CPUSet             // .used as CPUSet
	fset cpuset.CPUSet             // .full as CPUSet
	sort.Interface
	lessfn func ([]*NodeInfo, int, int) bool
}

// CPU cores in the system.
type cores struct {
	idle []*CpuInfo                // fully idle cores
	used []*CpuInfo                // partially allocated cores
	full []*CpuInfo                // fully allocated cores
	pick []*CpuInfo                // cores being picked/sorted
	iset cpuset.CPUSet             // .idle as CPUSet
	uset cpuset.CPUSet             // .used as CPUSet
	fset cpuset.CPUSet             // .full as CPUSet
	sort.Interface
	lessfn func ([]*CpuInfo, int, int) bool
}


// Discover and classify system packages.
func DiscoverPackages(sys *SystemInfo, idle *cpuset.CPUSet) *packages {
	p := &packages{
		idle: []*PackageInfo{},
		used: []*PackageInfo{},
		full: []*PackageInfo{},
	}
	p.Classify(sys, idle)
	return p
}

// Classify packages into idle, partially and fully allocated sets.
func (p *packages) Classify(sys *SystemInfo, idle *cpuset.CPUSet) {
	i := cpuset.NewBuilder()
	u := cpuset.NewBuilder()
	f := cpuset.NewBuilder()
	for _, pkg := range sys.Packages {
		cset := pkg.CPUSet()
		switch idle.Intersection(cset).Size() {
		case cset.Size():
			p.idle = append(p.idle, pkg)
			i.Add(pkg.Cpus()...)

		case 0:
			p.full = append(p.full, pkg)
			f.Add(pkg.Cpus()...)

		default:
			p.used = append(p.used, pkg)
			u.Add(pkg.Cpus()...)
		}
	}
	p.iset = i.Result()
	p.uset = u.Result()
	p.fset = f.Result()
}

// Package sorting interface.
func (p *packages) PickAll(pkg *PackageInfo) bool {
	return true
}

func (p *packages) PickNone(pkg *PackageInfo) bool {
	return false
}

func (p *packages) Len() int {
	return len(p.pick)
}

func (p *packages) Swap(i, j int) {
	p.pick[i], p.pick[j] = p.pick[j], p.pick[i]
}

func (p *packages) Less(i, j int) bool {
	return p.lessfn(p.pick, i, j)
}

func (p *packages) Pick(fIdle, fUsed, fFull func (*PackageInfo) bool) []*PackageInfo {
	p.pick = []*PackageInfo{}
	if fIdle != nil {
		for _, pkg := range p.idle {
			if fIdle(pkg) {
				p.pick = append(p.pick, pkg)
			}
		}
	}
	if fUsed != nil {
		for _, pkg := range p.used {
			if fUsed(pkg) {
				p.pick = append(p.pick, pkg)
			}
		}
	}
	if fFull != nil {
		for _, pkg := range p.used {
			if fFull(pkg) {
				p.pick = append(p.pick, pkg)
			}
		}
	}
	return p.pick
}

func (p *packages) Sort(lessfn func ([]*PackageInfo, int, int) bool) []*PackageInfo {
	p.lessfn = lessfn
	sort.Sort(p)
	return p.pick
}

// Discover and classify system NUMA nodes.
func DiscoverNodes(sys *SystemInfo, idle *cpuset.CPUSet) *nodes {
	n := &nodes{
		idle: []*NodeInfo{},
		used: []*NodeInfo{},
		full: []*NodeInfo{},
	}
	n.Classify(sys, idle)
	return n
}

// Classify nodes into idle, partially and fully allocated sets.
func (n *nodes) Classify(sys *SystemInfo, idle *cpuset.CPUSet) {
	i := cpuset.NewBuilder()
	u := cpuset.NewBuilder()
	f := cpuset.NewBuilder()
	for _, node := range sys.Nodes {
		cset := node.CPUSet()
		switch idle.Intersection(cset).Size() {
		case cset.Size():
			n.idle = append(n.idle, node)
			i.Add(node.Cpus()...)

		case 0:
			n.full = append(n.full, node)
			f.Add(node.Cpus()...)

		default:
			n.used = append(n.used, node)
			u.Add(node.Cpus()...)
		}
	}
	n.iset = i.Result()
	n.uset = u.Result()
	n.fset = f.Result()
}

// Node picking and sorting interface.
func (n *nodes) PickAll(node *NodeInfo) bool {
	return true
}

func (n *nodes) PickNone(node *NodeInfo) bool {
	return false
}

func (n *nodes) Len() int {
	return len(n.pick)
}

func (n *nodes) Swap(i, j int) {
	n.pick[i], n.pick[j] = n.pick[j], n.pick[i]
}

func (n *nodes) Less(i, j int) bool {
	return n.lessfn(n.pick, i, j)
}

func (n *nodes) Pick(fIdle, fUsed, fFull func (*NodeInfo) bool) []*NodeInfo {
	n.pick = []*NodeInfo{}
	if fIdle != nil {
		for _, node := range n.idle {
			if fIdle(node) {
				n.pick = append(n.pick, node)
			}
		}
	}
	if fUsed != nil {
		for _, node := range n.used {
			if fUsed(node) {
				n.pick = append(n.pick, node)
			}
		}
	}
	if fFull != nil {
		for _, node := range n.used {
			if fFull(node) {
				n.pick = append(n.pick, node)
			}
		}
	}

	return n.pick
}

func (n *nodes) Sort(lessfn func ([]*NodeInfo, int, int) bool) []*NodeInfo {
	n.lessfn = lessfn
	sort.Sort(n)
	return n.pick
}

// Discover and classify system cores.
func DiscoverCores(sys *SystemInfo, idle *cpuset.CPUSet) *cores {
	c := &cores{
		idle: []*CpuInfo{},
		used: []*CpuInfo{},
		full: []*CpuInfo{},
	}
	c.Classify(sys, idle)
	return c
}

// Classify cores into idle, partially and fully allocated sets.
func (c *cores) Classify(sys *SystemInfo, idle *cpuset.CPUSet) {
	i := cpuset.NewBuilder()
	u := cpuset.NewBuilder()
	f := cpuset.NewBuilder()
	for _, cpu := range sys.cpus {
		cset := cpu.CPUSet()
		switch idle.Intersection(cset).Size() {
		case cset.Size():
			c.idle = append(c.idle, cpu)
			i.Add(cpu.Cpus()...)

		case 0:
			c.used = append(c.used, cpu)
			u.Add(cpu.Cpus()...)

		default:
			c.full = append(c.full, cpu)
			f.Add(cpu.Cpus()...)
		}
	}
	c.iset = i.Result()
	c.uset = u.Result()
	c.fset = f.Result()
}

// System cores sorting interface.
func (c *cores) PickAll(cpu *CpuInfo) bool {
	return true
}

func (c *cores) PickNone(cpu *CpuInfo) bool {
	return false
}

func (c *cores) Len() int {
	return len(c.pick)
}

func (c *cores) Swap(i, j int) {
	c.pick[i], c.pick[j] = c.pick[j], c.pick[i]
}

func (c *cores) Less(i, j int) bool {
	return c.lessfn(c.pick, i, j)
}

func (c *cores) Pick(fIdle, fUsed, fFull func (*CpuInfo) bool) []*CpuInfo {
	c.pick = []*CpuInfo{}
	if fIdle != nil {
		for _, core := range c.idle {
			if fIdle(core) {
				c.pick = append(c.pick, core)
			}
		}
	}
	if fUsed != nil {
		for _, core := range c.used {
			if fUsed(core) {
				c.pick = append(c.pick, core)
			}
		}
	}
	if fFull != nil {
		for _, core := range c.used {
			if fFull(core) {
				c.pick = append(c.pick, core)
			}
		}
	}

	return c.pick
}

func (c *cores) Sort(lessfn func ([]*CpuInfo, int, int) bool) []*CpuInfo {
	c.lessfn = lessfn
	sort.Sort(c)
	return c.pick
}


// allocator encapuslates raw data and state for allocating and releasing CPUs.
type allocator struct {
	from *cpuset.CPUSet
	cnt int
	to *cpuset.CPUSet
	sys *SystemInfo
	idle cpuset.CPUSet
	packages *packages
	nodes *nodes
	cores *cores
	cset cpuset.CPUSet
}

// Create and initialize an allocator.
func newAllocator(from *cpuset.CPUSet, cnt int, to *cpuset.CPUSet) (*allocator, error) {
	sys, err := DiscoverSystemInfo("")
	if err != nil {
		return nil, err
	}

	idle := from.Clone()
	a := &allocator{
		from: from,
		cnt: cnt,
		sys: sys,
		idle: idle,
		packages: DiscoverPackages(sys, &idle),
		nodes: DiscoverNodes(sys, &idle),
		cores: DiscoverCores(sys, &idle),
		cset: cpuset.NewCPUSet(),
	}

	return a, nil
}

// Commit the allocation changes done so far.
func (a *allocator) commit() cpuset.CPUSet {
	*a.from = a.idle
	return a.cset
}

// Allocate allocates the requested number of CPU cores.
func (a *allocator) Allocate() cpuset.CPUSet {
	// First, allocate full idle packages (sockets) if possible.
	packages := a.packages.idle
	for _, pkg := range packages {
		if pkg.CpuCount() <= a.cnt {
			cset := pkg.CPUSet()
			a.cset = a.cset.Union(cset)
			a.idle = a.idle.Difference(cset)
			a.cnt -= cset.Size()

			if a.cnt == 0 {
				return a.commit()
			}

			if a.cnt < pkg.CpuCount() {
				break
			}
		}
	}

	// Next, allocate full idle NUMA nodes if possible.
	//     Sort idle nodes so that the ones which don't overlap
	//     with any idle packages come first. IOW, we try to keep
	//     idle packages intact for potential future full package
	//     allocations if at all possible.
	a.nodes.Pick(a.nodes.PickAll, nil, nil)
	nodes := a.nodes.Sort(func (nodes []*NodeInfo, i, j int) bool {
		// Prefer idle nodes that do not overlap with any idle packages.
		iset := nodes[i].CPUSet()
		if iset.Intersection(a.packages.iset).Size() == 0 {
			return true
		}
		return false
	})

	for _, node := range nodes {
		if node.CpuCount() <= a.cnt {
			cset := node.CPUSet()
			a.cset = a.cset.Union(cset)
			a.idle = a.idle.Difference(cset)
			a.cnt -= cset.Size()

			return a.commit()
		}
	}

	// Next, allocate full idle cores if possible.
	//     Sort idle cores so that the ones which don't overlap
	//     with any idle NUMA nodes come first. IOW, we try to keep
	//     idle NUMA nodes intact for potential future full node
	//     allocations if at all possible.
	a.cores.Pick(a.cores.PickAll, nil, nil)
	cores := a.cores.Sort(func (cores []*CpuInfo, i, j int) bool {
		iset := cores[i].CPUSet()
		if iset.Intersection(a.cores.iset).Size() == 0 {
			return true
		}
		return false
	})

	for _, core := range cores {
		if core.CpuCount() <= a.cnt {
			cset := core.CPUSet()
			a.cset = a.cset.Union(cset)
			a.idle = a.idle.Difference(cset)
			a.cnt -= cset.Size()

			if a.cnt == 0 {
				return a.commit()
			}

			if a.cnt < core.CpuCount() {
				break
			}
		}
	}

	// Allocate single threads to fulfill the remaining request.
	//     Sort threads so that used (but not full) cores come first.
	//     IOW, we try to keep idle full cores intact for potential
	//     future full core allocations and start breaking them up
	//     only if the current allocation cannot be fulfilled without.
	// Notes:
	//     Currently, with max. 2 HTs per core, we break up at most a
	//     single full idle core.
	for _, thread := range append(a.cores.used, a.cores.idle...) {
		cset := a.idle.Intersection(thread.CPUSet())
		if cset.Size() <= a.cnt {
			a.cset = a.cset.Union(cset)
		} else {
			cset = cpuset.NewCPUSet(cset.ToSlice()[0:a.cnt]...)
		}

		a.idle = a.idle.Difference(cset)
		a.cnt -= cset.Size()

		if a.cnt == 0 {
			return a.commit()
		}
	}

	return cpuset.NewCPUSet()
}

// AllocateMore allocates the requested number of additional CPU cores.
func (a *allocator) AllocateMore() cpuset.CPUSet {
	return cpuset.NewCPUSet()
}

// Release releases the requested number of CPU cores.
func (a *allocator) Release() {
	return
}

// AllocateCpus allocates the given number of CPUs from the given set.
func AllocateCpus(from *cpuset.CPUSet, cnt int) (cpuset.CPUSet, error) {
	if from.Size() < cnt {
		return cpuset.NewCPUSet(),
		    fmt.Errorf("can't allocate %d cpus from CPUSet %s", cnt, from.String())
	}

	if from.Size() == cnt {
		cset := from.Clone()
		*from = cpuset.NewCPUSet()
		return cset, nil
	}

	alloc, err := newAllocator(from, cnt, nil)
	if err != nil {
		return cpuset.NewCPUSet(), err
	}

	return alloc.Allocate(), nil
}

// AllocateMoreCpus allocates more CPUs from the given set.
func AllocateMoreCpus(from *cpuset.CPUSet, cnt int, to *cpuset.CPUSet) (cpuset.CPUSet, error) {
	if to == nil {
		cset, err := AllocateCpus(from, cnt)
		if err != nil {
			return cpuset.NewCPUSet(), err
		}
		*to = to.Union(cset)
		return cset, nil
	}

	if from.Size() < cnt {
		return cpuset.NewCPUSet(),
		    fmt.Errorf("can't allocate %d cpus from CPUSet %s", cnt, from.String())
	}

	if from.Size() == cnt {
		cset := from.Clone()
		*from = cpuset.NewCPUSet()
		return cset, nil
	}

	alloc, err := newAllocator(from, cnt, to)
	if err != nil {
		return cpuset.NewCPUSet(), err
	}

	return alloc.AllocateMore(), nil
}

// ReleaseCpus releases the given number of CPUs.
func ReleaseCpus(from *cpuset.CPUSet, cnt int, to *cpuset.CPUSet) error {
	if from.Size() < cnt {
		return fmt.Errorf("can't release %d cpus from CPUSet %s", cnt, from.String())
	}

	if from.Size() == cnt {
		*to = to.Union(*from)
		*from = cpuset.NewCPUSet()
		return nil
	}

	alloc, err := newAllocator(from, cnt, to)
	if err != nil {
		return err
	}

	alloc.Release()

	return nil
}











/*

// Allocator encapsulates data for allocating or releasing CPU cores.
type allocator struct {
	from *cpuset.CPUSet            // CPUSet to allocate from
	cnt int                        // number of CPUs to allocate
	aset cpuset.CPUSet             // allocated CPUSet
	idle cpuset.CPUSet             // the idle CPUSet to allocate from
	sys *SystemInfo                // system (topology) information
	packages []*PackageInfo        // idle packages
	pset cpuset.CPUSet             // ditto as a CPUSet
	nodes []*NodeInfo              // idle nodes, sorted by idle package disjointness
	nset cpuset.CPUSet             // ditto as a CPUSet
	cores []*CpuInfo               // idle cores, sorted by idle node disjointness
	cset cpuset.CPUSet             // ditto as a CPUSet
	threads []*CpuInfo             // idle threads
}

type nodeSorter struct {
	packages cpuset.CPUSet
	nodes []*NodeInfo
	sort.Interface
}

type coreSorter struct {
	nodes cpuset.CPUSet
	cores []*CpuInfo
	sort.Interface
}

// Create and initialize a new allocator.
func newAllocator(from *cpuset.CPUSet, cnt int) (*allocator, error) {
	sys, err := DiscoverSystemInfo("")
	if err != nil {
		return nil, err
	}

	a := &allocator{
		from: from,
		cnt: cnt,
		aset: cpuset.NewCPUSet(),
		idle: from.Clone(),
		sys: sys,
		packages: []*PackageInfo{},
		nodes: []*NodeInfo{},
		cores: []*CpuInfo{},
		threads: []*CpuInfo{},
	}

	a.idlePackages()
	a.idleNodes()
	a.idleCores()

	return a, nil
}

// Discover the set of idle full physical packages (sockets).
func (a *allocator) idlePackages() {
	b := cpuset.NewBuilder()
	for _, pkg := range a.sys.Packages {
		pset := pkg.CPUSet()
		if a.idle.Intersection(pset).Size() == pset.Size() {
			a.packages = append(a.packages, pkg)
			b.Add(pkg.Cpus()...)
		}
	}
	a.pset = b.Result()
}

func (s *nodeSorter) Len() int {
	return len(s.nodes)
}

func (s *nodeSorter) Less(i, j int) bool {
	iset := s.nodes[i].CPUSet()
	if iset.Intersection(s.packages).Size() == 0 {
		return true
	}
	return false
}

func (s *nodeSorter) Swap(i, j int) {
	s.nodes[i], s.nodes[j] = s.nodes[j], s.nodes[i]
}

// Discover the set of idle full NUMA nodes.
func (a *allocator) idleNodes() {
	b := cpuset.NewBuilder()
	for _, node := range a.sys.Nodes {
		nset := node.CPUSet()
		if a.idle.Intersection(nset).Size() == nset.Size() {
			a.nodes = append(a.nodes, node)
			b.Add(node.Cpus()...)
		}
	}
	a.nset = b.Result()

	s := nodeSorter{packages: a.pset.Clone(), nodes: a.nodes}
	sort.Sort(&s)
	a.nodes = s.nodes
}

func (s *coreSorter) Len() int {
	return len(s.cores)
}

func (s *coreSorter) Less(i, j int) bool {
	iset := s.cores[i].ThreadCPUSet()
	if iset.Intersection(s.nodes).Size() == 0 {
		return true
	}
	return false
}

func (s *coreSorter) Swap(i, j int) {
	s.cores[i], s.cores[j] = s.cores[j], s.cores[i]
}

// Discover the set of fully and partially idle cores.
func (a *allocator) idleCores() {
	b := cpuset.NewBuilder()
	for id, cpu := range a.sys.cpus {
		tset := cpu.ThreadCPUSet()
		if a.idle.Intersection(tset).Size() == tset.Size() {
			a.cores = append(a.cores, cpu)
			b.Add(id)
		} else if !tset.IsEmpty() {
			a.threads = append(a.threads, cpu)
		}
	}
	a.cset = b.Result()

	cs := coreSorter{nodes: a.nset.Clone(), cores: a.cores}
	sort.Sort(&cs)
	a.cores = cs.cores
}

// Allocate full idle pakcages (sockets) if possible.
func (a *allocator) allocatePackages() bool {
	for _, pkg := range a.packages {
		if pkg.CpuCount() <= a.cnt {
			cset := pkg.CPUSet()
			a.aset = a.aset.Union(cset)
			a.idle = a.idle.Difference(cset)
			a.cnt -= cset.Size()

			if a.cnt == 0 {
				return true
			}
		}
	}

	return false
}

// Allocate full idle NUMA nodes if possibe.
//   Nodes are sorted so that idle ones which don't overlap
//   with any idle packages come first. IOW, we try to keep
//   idle packages intact for potential future full package
//   allocations if at all possible.
func (a *allocator) allocateNodes() bool {
	for _, node := range a.nodes {
		if node.CpuCount() <= a.cnt {
			cset := node.CPUSet()
			a.aset = a.aset.Union(cset)
			a.idle = a.idle.Difference(cset)
			a.cnt -= cset.Size()

			if a.cnt == 0 {
				return true
			}
		}
	}

	return false
}

// Allocate full idle cores if possible.
//   Cores are sorted so that idle ones which don't overlap
//   with any idle nodes come first. IOW, we try to keep
//   idle NUMA nodes intact for potential future full node
//   allocations if at all possible.
func (a *allocator) allocateCores() bool {
	for _, core := range a.cores {
		if core.CpuCount() <= a.cnt {
			cset := core.CPUSet()
			a.aset = a.aset.Union(cset)
			a.idle = a.idle.Difference(cset)
			a.cnt -= cset.Size()

			if a.cnt == 0 {
				return true 
			}
		}

		// we assume identical cores
		if a.cnt < core.CpuCount() {
			return false
		}
	}

	return false
}

// Allocate single threads to fulfill the remaining request.
//   Threads are sorted so that cores with a busy thread come first.
//   IOW, we try to keep idle full cores intact for potential future
//   full core allocations and start breaking them up only if the
//   current allocation cannot be fulfilled otherwise.
// Note: Currently, with max. 2 HTs per core, we break up at most
//   a single full idle core.
func (a *allocator) allocateThreads() bool {
	for _, thread := range append(a.threads, a.cores...) {
		cset := a.idle.Intersection(thread.CPUSet())
		if cset.Size() <= a.cnt {
			a.aset = a.aset.Union(cset)
			a.idle = a.idle.Difference(cset)
			a.cnt -= cset.Size()
		} else {
			cset = cpuset.NewCPUSet(cset.ToSlice()[0:a.cnt]...)
			a.aset = a.aset.Union(cset)
			a.idle = a.idle.Difference(cset)
			a.cnt -= cset.Size()
		}

		if a.cnt == 0 {
			return true
		}
	}

	return false
}

// Commit the current allocation (write updated idle set to the original one).
func (a *allocator) commit() cpuset.CPUSet {
	*a.from = a.idle
	return a.aset
}

// AllocateCpus allocates the given number of CPUs from the given set.
func AllocateCpus(from *cpuset.CPUSet, cnt int) (cpuset.CPUSet, error) {
	if from.Size() < cnt {
		return cpuset.NewCPUSet(),
		    fmt.Errorf("can't allocate %d cpus from CPUSet %s", cnt, from.String())
	}

	if from.Size() == cnt {
		cset := *from
		*from = cpuset.NewCPUSet()
		return cset, nil
	}

	alloc, err := newAllocator(from, cnt)
	if err != nil {
		return cpuset.NewCPUSet(), err
	}

	if alloc.allocatePackages() || alloc.allocateNodes() ||
		alloc.allocateCores() || alloc.allocateThreads() {
		return alloc.commit(), nil
	}

	return cpuset.NewCPUSet(),
	    fmt.Errorf("failed to allocate %d cpus from CPUSet %s", cnt, from.String())
}

// AllocateMoreCpus allocates more CPUs from the given set.
func AllocateMoreCpus(from *cpuset.CPUSet,  to *cpuset.CPUSet, cnt int) error {
	return nil
}

// ReleaseCpus releases the given number of CPUs.
func ReleaseCpus(from *cpuset.CPUSet, to *cpuset.CPUSet, cnt int) error {
	return nil
}

*/
