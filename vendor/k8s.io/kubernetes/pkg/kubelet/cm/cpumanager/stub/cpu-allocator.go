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

// Allocator encapsulates the necessary data for allocating CPU cores
type allocator struct {
	from *cpuset.CPUSet            // CPUSet to allocate from
	cnt int                        // number of CPUs to allocate
	aset cpuset.CPUSet             // allocated CPUSet
	idle cpuset.CPUSet             // the idle CPUset to allocate from
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

/*
	var cset cpuset.CPUSet

	free := from.Clone()
	aset := cpuset.NewCPUSet()


	// allocate full idle packages (sockets), if possible
	for _, pkg := range alloc.packages {
		if pkg.CpuCount() <= cnt {
			cset = pkg.CPUSet()
			aset = aset.Union(cset)
			free = free.Difference(cset)
			cnt -= cset.Size()

			if cnt == 0 {
				goto done
			}
		}

		if cnt < pkg.CpuCount() {
			break // we assume equally sized physical packages
		}
	}

	if cnt == 0 {
		goto done
	}

	// allocate full idle NUMA nodes, if possible
	//     Nodes are sorted so that idle nodes which don't overlap
	//     with any idle packages come first, if we have such nodes.
	for _, node := range alloc.nodes {
		if node.CpuCount() <= cnt {
			cset = node.CPUSet()
			aset = aset.Union(cset)
			free = free.Difference(cset)
			cnt -= cset.Size()

			if cnt == 0 {
				break
			}
		}
	}

	if cnt == 0 {
		goto done
	}

	// allocate full idle cores, if possible
	//    Cores are sorted so that idle cores which don't overlap
	//    with any idle nodes come first, if we have such cores.
	for _, core := range alloc.cores {
		if core.CpuCount() <= cnt {
			cset = core.CPUSet()
			aset = aset.Union(cset)
			free = free.Difference(cset)
			cnt -= cset.Size()

			if cnt == 0 || cnt < core.CpuCount() {
				break // we assume equally sized cores
			}
		}
	}

	if cnt == 0 {
		goto done
	}

	// allocate single threads to fulfill the remaining request
	//    If there are not enough single threads break up full idle
	//    cores for the remaining allocations.
	for _, thread := range append(alloc.threads, alloc.cores...) {
		cset = free.Intersection(thread.CPUSet())
		if cset.Size() <= cnt {
			aset = aset.Union(cset)
			free = free.Difference(cset)
			cnt -= cset.Size()
		} else {
			cset = cpuset.NewCPUSet(cset.ToSlice()[0:cnt]...)

			aset = aset.Union(cset)
			free = free.Difference(cset)
			cnt -= cset.Size()
		}

		if cnt == 0 {
			break
		}
	}

done:
	*from = free
	return aset, nil
*/
}

// AllocateMoreCpus allocates more CPUs from the given set.
func AllocateMoreCpus(from *cpuset.CPUSet,  to *cpuset.CPUSet, cnt int) error {
	return nil
}

// ReleaseCpus releases the given number of CPUs.
func ReleaseCpus(from *cpuset.CPUSet, to *cpuset.CPUSet, cnt int) error {
	return nil
}
