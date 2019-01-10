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

// CPU allocation preference
const (
	TryIdlePackages = 1 << iota  // try fully idle packages
	TryIdleNodes                 // try fully idle NUMA nodes
	TryIdleCores                 // try fully idle cores
)

// Not sure whether/how using NUMA topology for allocating would make sense, so omit it.
var allocationPreference = TryIdlePackages /*| TryIdleNodes*/ | TryIdleCores


// An unordered set of integer ids.
type idset map[int]struct{}

// Physical packages in the system.
type packages struct {
	sys *SystemInfo                // system/topology information
	idle idset                     // set of idle packages
	used idset                     // set of partially used packages
	full idset                     // set of fully used packages
	pick []int                     // ids of packages being picked/sorted
	iset cpuset.CPUSet             // .idle as CPUSet
	uset cpuset.CPUSet             // .used as CPUSet
	fset cpuset.CPUSet             // .full as CPUSet
	sort.Interface
	lessfn func (*PackageInfo, *PackageInfo) bool
}

// NUMA nodes in the system.
type nodes struct {
	sys *SystemInfo                // system/topology information
	idle idset                     // set of idle nodes
	used idset                     // set of partially used nodes
	full idset                     // set of fully used nodes
	pick []int                     // ids of nodes being picked/sorted
	iset cpuset.CPUSet             // .idle as CPUSet
	uset cpuset.CPUSet             // .used as CPUSet
	fset cpuset.CPUSet             // .full as CPUSet
	sort.Interface
	lessfn func (*NodeInfo, *NodeInfo) bool
}

// CPU cores in the system.
type cores struct {
	sys *SystemInfo                // system/topology information
	idle idset                     // set if idle cores
	used idset                     // set of partially used cores
	full idset                     // set of fully used cores
	pick []int                     // ids of cores being picked/sorted
	iset cpuset.CPUSet             // .idle as CPUSet
	uset cpuset.CPUSet             // .used as CPUSet
	fset cpuset.CPUSet             // .full as CPUSet
	sort.Interface
	lessfn func (*CpuInfo, *CpuInfo) bool
}

// allocator encapsulates raw data and state for allocating and releasing CPUs.
type allocator struct {
	cnt       int                  // number of CPU cores to allocate/free
	from     *cpuset.CPUSet        // set of CPU cores to allocate/free from
	sys      *SystemInfo           // system/topology information to use
	packages *packages             // physical packages
	nodes    *nodes                // NUMA nodes
	cores    *cores                // CPU cores
	idle      cpuset.CPUSet        // idle set of CPU cores
	cset      cpuset.CPUSet        // set of CPU cores being allocated/freed
}


// NewIdSet creates a new empty id set.
func NewIdSet() idset {
	return make(map[int]struct{})
}

// Add adds the given id to the set.
func (s idset) Add(id int) bool {
	_, present := s[id]
	if !present {
		s[id] = struct{}{}
	}
	return present
}

// Del removes the given id from the set.
func (s idset) Del(id int) bool {
	_, present := s[id]
	if present {
		delete(s, id)
	}
	return present
}

// Has tests if the set contains the given id.
func (s idset) Has(id int) bool {
	_, present := s[id]
	return present
}

// Members returns the ids present in the set as a slice.
func (s idset) Members() []int {
	ids := []int{}
	for id := range s {
		ids = append(ids, id)
	}
	return ids
}

// SortedMembers returns the ids present in the set as a sorted slice.
func (s idset) SortedMembers() []int {
	ids := []int{}
	for id := range s {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

// Classify packages into idle, partially and fully allocated sets.
func (p *packages) Classify(idle cpuset.CPUSet) {
	p.idle = NewIdSet()
	p.used = NewIdSet()
	p.full = NewIdSet()
	i := cpuset.NewBuilder()
	u := cpuset.NewBuilder()
	f := cpuset.NewBuilder()
	for _, pkg := range p.sys.Packages {
		cset := pkg.CPUSet().Difference(p.sys.Offline)
		switch idle.Intersection(cset).Size() {
		case cset.Size():
			p.idle.Add(pkg.Id)
			i.Add(cset.ToSlice()...)

		case 0:
			p.full.Add(pkg.Id)
			f.Add(cset.ToSlice()...)

		default:
			p.used.Add(pkg.Id)
			u.Add(cset.ToSlice()...)
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
	return p.lessfn(p.sys.Packages[p.pick[i]], p.sys.Packages[p.pick[j]])
}

func (p *packages) Pick(fIdle, fUsed, fFull func (*PackageInfo) bool) []int {
	p.pick = []int{}
	if fIdle != nil {
		for _, id := range p.idle.SortedMembers() {
			if fIdle(p.sys.Packages[id]) {
				p.pick = append(p.pick, id)
			}
		}
	}
	if fUsed != nil {
		for _, id := range p.used.SortedMembers() {
			if fUsed(p.sys.Packages[id]) {
				p.pick = append(p.pick, id)
			}
		}
	}
	if fFull != nil {
		for _, id := range p.full.SortedMembers() {
			if fFull(p.sys.Packages[id]) {
				p.pick = append(p.pick, id)
			}
		}
	}

	return p.pick
}

func (p *packages) Sort(lessfn func (*PackageInfo, *PackageInfo) bool) []int {
	p.lessfn = lessfn
	sort.Sort(p)
	return p.pick
}

// Classify nodes into idle, partially and fully allocated sets.
func (n *nodes) Classify(idle cpuset.CPUSet) {
	n.idle = NewIdSet()
	n.used = NewIdSet()
	n.full = NewIdSet()
	i := cpuset.NewBuilder()
	u := cpuset.NewBuilder()
	f := cpuset.NewBuilder()
	for _, node := range n.sys.Nodes {
		cset := node.CPUSet().Difference(n.sys.Offline)
		switch idle.Intersection(cset).Size() {
		case cset.Size():
			n.idle.Add(node.Id)
			i.Add(cset.ToSlice()...)

		case 0:
			n.full.Add(node.Id)
			f.Add(cset.ToSlice()...)

		default:
			n.used.Add(node.Id)
			u.Add(cset.ToSlice()...)
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
	return n.lessfn(n.sys.Nodes[n.pick[i]], n.sys.Nodes[n.pick[j]])
}

func (n *nodes) Pick(fIdle, fUsed, fFull func (*NodeInfo) bool) []int {
	n.pick = []int{}
	if fIdle != nil {
		for _, id := range n.idle.SortedMembers() {
			if fIdle(n.sys.Nodes[id]) {
				n.pick = append(n.pick, id)
			}
		}
	}
	if fUsed != nil {
		for _, id := range n.used.SortedMembers() {
			if fUsed(n.sys.Nodes[id]) {
				n.pick = append(n.pick, id)
			}
		}
	}
	if fFull != nil {
		for _, id := range n.full.SortedMembers() {
			if fFull(n.sys.Nodes[id]) {
				n.pick = append(n.pick, id)
			}
		}
	}

	return n.pick
}

func (n *nodes) Sort(lessfn func (*NodeInfo, *NodeInfo) bool) []int {
	n.lessfn = lessfn
	sort.Sort(n)
	return n.pick
}

// Classify cores into idle, partially and fully allocated sets.
func (c *cores) Classify(idle cpuset.CPUSet) {
	c.idle = NewIdSet()
	c.used = NewIdSet()
	c.full = NewIdSet()
	i := cpuset.NewBuilder()
	u := cpuset.NewBuilder()
	f := cpuset.NewBuilder()
	for _, cpu := range c.sys.cpus {
		cset := cpu.CPUSet().Difference(c.sys.Offline)
		switch idle.Intersection(cset).Size() {
		case cset.Size():
			c.idle.Add(cpu.Id)
			i.Add(cset.ToSlice()...)

		case 0:
			c.full.Add(cpu.Id)
			f.Add(cset.ToSlice()...)

		default:
			c.used.Add(cpu.Id)
			u.Add(cset.ToSlice()...)
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
	return c.lessfn(c.sys.cpus[c.pick[i]], c.sys.cpus[c.pick[j]])
}

func (c *cores) Pick(fIdle, fUsed, fFull func (*CpuInfo) bool) []int {
	c.pick = []int{}
	if fIdle != nil {
		for _, id := range c.idle.SortedMembers() {
			if fIdle(c.sys.cpus[id]) {
				c.pick = append(c.pick, id)
			}
		}
	}
	if fUsed != nil {
		for _, id := range c.used.SortedMembers() {
			if fUsed(c.sys.cpus[id]) {
				c.pick = append(c.pick, id)
			}
		}
	}
	if fFull != nil {
		for _, id := range c.full.SortedMembers() {
			if fFull(c.sys.cpus[id]) {
				c.pick = append(c.pick, id)
			}
		}
	}

	return c.pick
}

func (c *cores) Sort(lessfn func (*CpuInfo, *CpuInfo) bool) []int {
	c.lessfn = lessfn
	sort.Sort(c)
	return c.pick
}

// Create and initialize an allocator.
func newAllocator(from *cpuset.CPUSet, cnt int, to *cpuset.CPUSet) (*allocator, error) {
	sys, err := DiscoverSystemInfo("")
	if err != nil {
		return nil, err
	}

	a := &allocator{
		from: from,
		cnt: cnt,
		sys: sys,
		idle: from.Clone(),
		packages: &packages{sys: sys},
		nodes: &nodes{sys: sys},
		cores: &cores{sys: sys},
	}

	return a, nil
}

// Commit the allocation changes and return the allocated set.
func (a *allocator) commit() cpuset.CPUSet {
	*a.from = a.idle
	return a.cset
}

// Abort the allocation changes and return an empty set.
func (a *allocator) abort(reset_idle bool) cpuset.CPUSet {
	if reset_idle {
		a.idle = a.from.Clone()
	}
	return cpuset.NewCPUSet()
}

// Allocate fully idle physical packages if possible.
func (a *allocator) takePackages() {
	if (allocationPreference & TryIdlePackages) == 0 {
		return
	}

	a.packages.Classify(a.idle)

	took := false
	for _, id := range a.packages.idle.SortedMembers() {
		pkg := a.sys.Packages[id]
		cset := pkg.CPUSet().Difference(a.sys.Offline)

		if cset.Size() > a.cnt {
			continue
		}

		a.cset = a.cset.Union(cset)
		a.idle = a.idle.Difference(cset)
		a.cnt -= cset.Size()
		took = true

		if a.cnt == 0 {
			break
		}
	}
	if took {
		a.packages.Classify(a.idle)
	}
}

// Allocate fully idle NUMA nodes if possible.
func (a *allocator) takeNodes() {
	if (allocationPreference & TryIdleNodes) == 0 {
		return
	}

	a.nodes.Classify(a.idle)

	// Sort idle NUMA nodes so that the ones which don't
	// overlap with any idle packages come first. IOW, we
	// try to keep idle packages intact for potential future
	// full package allocations if possible. In case of a tie
	// choose the node with the lower id.
	a.nodes.Pick(a.nodes.PickAll, nil, nil)
	nodes := a.nodes.Sort(func (inode, jnode *NodeInfo) bool {
		iolap := inode.CPUSet().Intersection(a.packages.iset).Size()
		jolap := jnode.CPUSet().Intersection(a.packages.iset).Size()

		if iolap == 0 && jolap == 0 {
			// Prefer larger idle nodes (assumed to have fewer offline CPUs).
			isize := inode.CPUSet().Difference(a.sys.Offline).Size()
			jsize := jnode.CPUSet().Difference(a.sys.Offline).Size()

			if isize > jsize {
				return true
			}

			if isize == jsize {
				return inode.Id < jnode.Id
			}

			return false
		}

		if iolap != 0 && jolap != 0 {
			return inode.Id < jnode.Id
		}

		if iolap == 0 {
			return true
		}

		return false
	})

	took := false
	for _, id := range nodes {
		node := a.sys.Nodes[id]
		cset := node.CPUSet().Difference(a.sys.Offline)

		if cset.Size() > a.cnt {
			continue
		}

		if a.idle.Intersection(cset).Size() < cset.Size() {
			continue
		}

		a.cset = a.cset.Union(cset)
		a.idle = a.idle.Difference(cset)
		a.cnt -= cset.Size()
		took = true

		if a.cnt == 0 {
			break
		}
	}
	if took {
		a.nodes.Classify(a.idle)
	}
}

// Allocate fully idle cores if possible.
func (a *allocator) takeCores() {
	if (allocationPreference & TryIdleCores) == 0 {
		return
	}

	a.cores.Classify(a.idle)

	// Pick and sort idle cores so that the ones which don't overlap with
	// any idle NUMA nodes come first. IOW, we try to keep idle NUMA nodes
	// intact for potential future full node allocations if possible.
	cores := a.cores.Pick(a.cores.PickAll, nil, nil)
	if (allocationPreference & TryIdleNodes) != 0 {
		cores = a.cores.Sort(func (icore, jcore *CpuInfo) bool {
			iolap := icore.CPUSet().Intersection(a.nodes.iset).Size()
			jolap := jcore.CPUSet().Intersection(a.nodes.iset).Size()

			if iolap == 0 && jolap == 0 {
				isize := icore.CPUSet().Difference(a.sys.Offline).Size()
				jsize := jcore.CPUSet().Difference(a.sys.Offline).Size()

				// Prefer larger idle cores (assumed to have fewer offline CPUs).
				if isize > jsize {
					return true
				}

				if isize == jsize {
					return icore.Id < jcore.Id
				}

				return false
			}

			if iolap != 0 && jolap != 0 {
				return icore.Id < jcore.Id
			}

			if iolap == 0 {
				return true
			}

			return false
		})
	} else {
		cores = a.cores.Sort(func (icore, jcore *CpuInfo) bool {
			// Prefer larger idle cores (assumed to have fewer offline CPUs).
			isize := icore.CPUSet().Difference(a.sys.Offline).Size()
			jsize := jcore.CPUSet().Difference(a.sys.Offline).Size()

			if isize > jsize {
				return true
			}

			if isize == jsize {
				return icore.Id < jcore.Id
			}

			return false
		})
	}

	took := false
	for _, id := range cores {
		core := a.sys.cpus[id]
		cset := core.CPUSet().Difference(a.sys.Offline)

		if cset.Size() > a.cnt {
			continue
		}

		if a.idle.Intersection(cset).Size() < cset.Size() {
			continue
		}

		a.cset = a.cset.Union(cset)
		a.idle = a.idle.Difference(cset)
		a.cnt -= cset.Size()

		if a.cnt == 0 || a.cnt < core.CpuCount() {
			break
		}
	}
	if took {
		a.cores.Classify(a.idle)
	}
}

// Allocate idle threads from partially used or fully idle cores as necessary.
func (a *allocator) takeThreads() {
	for _, id := range a.cores.used.SortedMembers() {
		thread := a.sys.cpus[id]
		cset := a.idle.Intersection(thread.CPUSet().Difference(a.sys.Offline))

		if cset.Size() > a.cnt {
			cset = cpuset.NewCPUSet(cset.ToSlice()[0:a.cnt]...)
		}

		a.cset = a.cset.Union(cset)
		a.idle = a.idle.Difference(cset)
		a.cnt -= cset.Size()

		if a.cnt == 0 {
			return
		}
	}

	for _, id := range a.cores.idle.SortedMembers() {
		core := a.sys.cpus[id]
		cset := a.idle.Intersection(core.CPUSet().Difference(a.sys.Offline))

		if cset.Size() > a.cnt {
			cset = cpuset.NewCPUSet(cset.ToSlice()[0:a.cnt]...)
		}

		a.cset = a.cset.Union(cset)
		a.idle = a.idle.Difference(cset)
		a.cnt -= cset.Size()

		if a.cnt == 0 {
			return
		}
	}
}

// Allocate allocates the requested number of CPU cores.
func (a *allocator) Allocate() cpuset.CPUSet {
	a.takePackages()
	if a.cnt == 0 {
		return a.commit()
	}

	a.takeNodes()
	if a.cnt == 0 {
		return a.commit()
	}

	a.takeCores()
	if a.cnt == 0 {
		return a.commit()
	}

	a.takeThreads()
	if a.cnt == 0 {
		return a.commit()
	}

	return a.abort(false)
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

// ReleaseCpus releases the given number of CPUs.
func ReleaseCpus(from *cpuset.CPUSet, cnt int) (cpuset.CPUSet, error) {
	if from.Size() < cnt {
		return cpuset.NewCPUSet(),
		    fmt.Errorf("can't release %d cpus from CPUSet %s", cnt, from.String())
	}

	if from.Size() == cnt {
		cset := from.Clone()
		*from = cpuset.NewCPUSet()
		return cset, nil
	}

	alloc, err := newAllocator(from, from.Size() - cnt, nil)
	if err != nil {
		return cpuset.NewCPUSet(), err
	}

	kept := alloc.Allocate()
	cset := from.Difference(kept)
	*from = kept

	return cset, nil
}


