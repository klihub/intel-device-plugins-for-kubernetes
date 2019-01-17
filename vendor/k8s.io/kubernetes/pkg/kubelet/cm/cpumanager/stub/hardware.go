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
	"os"
	"path/filepath"
	"strings"
	"strconv"
	"io/ioutil"

	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
)

const (
	defaultSysfs = "/sys"
	sysfsSystemPath = "devices/system"
)

//
// hardware information
//

// SystemInfo provides information about the running hardware.
type SystemInfo struct {
	Path string                   // sysfs device/system path
	Cpus map[int]*CpuInfo         // CPU core information
	Nodes map[int]*NodeInfo       // NUMA node information
	Packages map[int]*PackageInfo // physical package information
	Offline cpuset.CPUSet         // offline CPUs
	Isolated cpuset.CPUSet        // kernel isolated CPUs
}

// CpuInfo provides details about a single CPU/core.
type CpuInfo struct {
	Path string            // sysfs path for this CPU/core
	Id int                 // kernel CPU id
	NodeId int             // NUMA node id
	PackageId int          // physical package id
	Cores []int            // cores in the same package
	Threads []int          // hyperthreads in the same core
	MinFreq int            // lowest frequency if known
	MaxFreq int            // highest frequency if known
	Online bool            // whether CPU is online
}

// NodeInfo provides infromation about a NUMA node.
type NodeInfo struct {
	Path string            // sysfs path for this node
	Id int                 // node id
	Distance []int         // distance from other nodes
	Cpus []int             // cores in this node
}

// PackageInfo provides information about a single physical package.
type PackageInfo struct {
	Id int                 // physical package id
	Cpus []int             // cores in this node
	Nodes []int            // NUMA nodes, if any
}

// Cached SystemInfo for DiscoverSystemInfo.
var sysinfo *SystemInfo

// DiscoverSystemInfo collects information about the running system.
func DiscoverSystemInfo(sysfs string) (*SystemInfo, error) {
	if sysinfo != nil {
		return sysinfo, nil
	}

	sysinfo := &SystemInfo{}
	if err := sysinfo.Discover(sysfs); err != nil {
		return nil, err
	} else {
		return sysinfo, nil
	}
}

// Discover discovers information about the running system.
func (s *SystemInfo) Discover(sysfs string) error {
	if s.Path != "" {
		return nil
	}
	if sysfs == "" {
		sysfs = defaultSysfs
	}

	s.Path = filepath.Join(sysfs, sysfsSystemPath)
	s.Cpus = make(map[int]*CpuInfo)
	s.Nodes = make(map[int]*NodeInfo)
	s.Packages = make(map[int]*PackageInfo)

	if err := s.DiscoverCpus(); err != nil {
		return err
	}
	if err := s.DiscoverNodes(); err != nil {
		return err
	}
	if err := s.DiscoverPackages(); err != nil {
		return err
	}

	kcl, err := GetKernelCmdline()
	if err != nil {
		return err
	} else {
		if cset, err := kcl.IsolatedCPUSet(); err != nil {
			return err
		} else {
			s.Isolated = cset
		}
	}

	return nil
}

// DiscoverCpus discovers CPU hardware/topology information from sysfs.
func (s *SystemInfo) DiscoverCpus() error {
	var entries []os.FileInfo
	var err error

	path := filepath.Join(s.Path, "cpu")
	if entries, err = ioutil.ReadDir(path); err != nil {
		return err
	}

	offline := cpuset.NewBuilder()
	for _, entry := range entries {
		var name string
		var id int

		if name = entry.Name(); name[0:3] != "cpu" {
			continue
		}
		if id = getNameEnumeration(name); id < 0 {
			continue
		}

		cpu := &CpuInfo{Path: filepath.Join(path, name), Id: id}
		if err = cpu.Discover(); err != nil {
			return err
		}
		s.Cpus[id] = cpu
		if !cpu.Online {
			offline.Add(id)
		}
	}
	s.Offline = offline.Result()

	return nil
}

// DiscoverNodes discovers NUMA node topology/information from sysfs.
func (s *SystemInfo) DiscoverNodes() error {
	var entries []os.FileInfo
	var err error

	path := filepath.Join(s.Path, "node")
	if entries, err = ioutil.ReadDir(path); err != nil {
		return err
	}
	for _, entry := range entries {
		var name string
		var id int

		if name = entry.Name(); name[0:4] != "node" {
			continue
		}
		if id = getNameEnumeration(name); id < 0 {
			continue
		}

		node := &NodeInfo{Path: filepath.Join(path, name), Id: id}
		if err = node.Discover(); err != nil {
			return err
		}
		s.Nodes[id] = node
	}

	return nil
}

// DiscoverPackages discovers physical package (socket) information from sysfs.
func (s *SystemInfo) DiscoverPackages() error {
	var pkg *PackageInfo
	var cpu *CpuInfo
	var ok bool

	for _, cpu = range s.Cpus {
		if pkg, ok = s.Packages[cpu.PackageId]; ok {
			pkg.Cpus = append(pkg.Cpus, cpu.Id)
		} else {
			pkg = &PackageInfo{
				Id: cpu.PackageId,
				Cpus: []int{cpu.Id},
				Nodes: []int{},
			}
			s.Packages[cpu.PackageId] = pkg
		}

		if len(s.Nodes) > 1 {
			present := false
			for _, n := range pkg.Nodes {
				if n == cpu.NodeId {
					present = true
					break
				}
			}
			if !present {
				pkg.Nodes = append(pkg.Nodes, cpu.NodeId)
			}
		}
	}

	return nil
}

// CpuCount returns the number of CPUs in the system.
func (s *SystemInfo) CpuCount() int {
	return len(s.Cpus)
}

// Cpus returns gathered info for all the CPUs in the system.
func (s *SystemInfo) CpuMap() map[int]*CpuInfo {
	return s.Cpus
}

// CPUSet returns the ids of all CPUs in the system as a CPUSet.
func (s *SystemInfo) CPUSet() cpuset.CPUSet {
	b := cpuset.NewBuilder()
	for id, _ := range s.Cpus {
		b.Add(id)
	}
	return b.Result()
}

// OnlineCPUSet returns the CPUSet of online CPUs.
func (s *SystemInfo) OnlineCPUSet() cpuset.CPUSet {
	return s.CPUSet().Difference(s.Offline)
}

// OfflineCPUSet returns the the CPUSet of offline CPUs.
func (s *SystemInfo) OfflineCPUSet() cpuset.CPUSet {
	return s.Offline.Clone() // is Clone necessary ?
}

// IsolatedCpus returns the ids of kernel-isolated CPUs.
func (s *SystemInfo) IsolatedCpus() []int {
	return s.Isolated.ToSlice()
}

// IsolatedCPUSet returns the CPUSet of kernel-isolated CPUs.
func (s *SystemInfo) IsolatedCPUSet() cpuset.CPUSet {
	return s.Isolated
}

// Set the given CPU online/offline
func (s *SystemInfo) SetOffline(cpuId int, offline bool) error {
	if cpu, ok := s.Cpus[cpuId]; !ok {
		return fmt.Errorf("no CPU #%d", cpuId)
	} else {
		f, err := os.OpenFile(filepath.Join(cpu.Path, "online"), os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("CPU#%d: can't set online/offline: %v", cpuId, err)
		}

		setting := []byte{' ', '\n'}
		if !offline {
			setting[0] = '1'
		} else {
			setting[0] = '0'
		}

		if _, err = f.Write(setting); err != nil {
			return fmt.Errorf("CPU#%d: can't set online/offline: %v", cpuId, err)
		}
	}

	return nil
}

// PackageCount returns the number of physical packages in the system.
func (s *SystemInfo) PackageCount() int {
	return len(s.Packages)
}

// PackageCpuCount returns the number of CPUs in the given physical package.
func (s *SystemInfo) PackageCpuCount(pkg int) int {
	if pkg, ok := s.Packages[pkg]; ok {
		return len(pkg.Cpus)
	} else {
		return 0
	}
}

// PackageCpus returns the ids of the CPUs in the given package.
func (s *SystemInfo) PackageCpus (pkgId int) []int {
	if pkg, ok := s.Packages[pkgId]; ok {
		return pkg.Cpus
	} else {
		return []int{}
	}
}

// PackageCPUSet returns the CPUs in the given package as a CPUSet.
func (s *SystemInfo) PackageCPUSet(pkgId int) cpuset.CPUSet {
	if pkg, ok := s.Packages[pkgId]; ok {
		return cpuset.NewCPUSet(pkg.Cpus...)
	} else {
		return cpuset.NewCPUSet()
	}
}

// NodeCount returns the number of NUMA nodes in the system.
func (s *SystemInfo) NodeCount() int {
	if len(s.Nodes) > 1 {
		return len(s.Nodes)
	} else {
		return 0
	}
}

// NodeCpuCount returns the number of CPUs local to the given node.
func (s *SystemInfo) NodeCpuCount(node int) int {
	if node, ok := s.Nodes[node]; ok {
		return len(node.Cpus)
	} else {
		return 0
	}
}

// NodeCpus returns the ids of the CPUs local to the given node.
func (s *SystemInfo) NodeCpus(nodeId int) []int {
	if node, ok := s.Nodes[nodeId]; ok {
		return node.Cpus
	} else {
		return []int{}
	}
}

// NodeCPUSet returns the CPUs local to the given node as a CPUSet.
func (s *SystemInfo) NodeCPUSet(nodeId int) cpuset.CPUSet {
	if node, ok := s.Nodes[nodeId]; ok {
		return cpuset.NewCPUSet(node.Cpus...)
	} else {
		return cpuset.NewCPUSet()
	}
}

// ThreadCpus return the ids of all threads for the given CPU (core).
func (s *SystemInfo) ThreadCpus(cpuId int) []int {
	if cpu, ok := s.Cpus[cpuId]; ok {
		return cpu.Threads
	} else {
		return []int{}
	}
}

// ThreadCPUSet returns the ids of all threads for the given CPU (core) as a CPUSet.
func (s *SystemInfo) ThreadCPUSet(cpuId int) cpuset.CPUSet {
	if cpu, ok := s.Cpus[cpuId]; ok {
		return cpuset.NewCPUSet(cpu.Threads...)
	} else {
		return cpuset.NewCPUSet()
	}
}

// ThreadSiblingCPUSet returns the thread sibling CPUSet for the given CPU.
func (s *SystemInfo) ThreadSiblingCPUSet(cpuId int, excludeCpuId bool) cpuset.CPUSet {
	if cpu, ok := s.Cpus[cpuId]; !ok {
		return cpuset.NewCPUSet()
	} else {
		tset := cpu.CPUSet()
		if excludeCpuId {
			tset = tset.Difference(cpuset.NewCPUSet(cpuId))
		}
		return tset
	}
}

// Dump SystemInfo details.
func (s *SystemInfo) Dump() {
	fmt.Printf("  %d packages:\n", len(s.Packages))
	for id := 0; id < len(s.Packages); id++ {
		pkg := s.Packages[id]
		fmt.Printf("    #%d: %+v\n", id, *pkg)
	}
	fmt.Printf("  %d nodes:\n", len(s.Nodes))
	for id := 0; id < len(s.Nodes); id++ {
		node := s.Nodes[id]
		fmt.Printf("    #%d: %+v\n", id, *node)
	}
	fmt.Printf("  %d cpus: (%s)\n", len(s.Cpus), s.CPUSet().String())
	for id := 0; id < len(s.Cpus); id++ {
		cpu := s.Cpus[id]
		fmt.Printf("    #%d, pkg %d, node %d: cores: %+v, threads: %+v\n", id,
			cpu.PackageId, cpu.NodeId, cpu.Cores, cpu.Threads)
	}
}

// Discover discovers hardware/topology information for a CPU.
func (cpu *CpuInfo) Discover() error {
	var nodes []string
	var err error

	path := filepath.Join(cpu.Path, "node[0-9]*")
	if nodes, err = filepath.Glob(path); err != nil {
		return err
	}
	if len(nodes) == 1 {
		if cpu.NodeId = getNameEnumeration(nodes[0]); cpu.NodeId < 0 {
			return fmt.Errorf("failed to discover node for CPU#%d", cpu.Id)
		}
	} else {
		cpu.NodeId = -1
	}
	if _, err = getSysfsEntry(cpu.Path, "topology/physical_package_id", &cpu.PackageId); err != nil {
		return err
	}
	if _, err = getSysfsEntry(cpu.Path, "topology/core_siblings_list", &cpu.Cores); err != nil {
		return err
	}
	if _, err = getSysfsEntry(cpu.Path, "topology/thread_siblings_list", &cpu.Threads); err != nil {
		return err
	}
	if _, err = getSysfsEntry(cpu.Path, "cpufreq/cpuinfo_min_freq", &cpu.MinFreq); err != nil {
		cpu.MinFreq = 0
	}
	if _, err = getSysfsEntry(cpu.Path, "cpufreq/cpuinfo_max_freq", &cpu.MaxFreq); err != nil {
		cpu.MaxFreq = 0
	}
	if _, err = getSysfsEntry(cpu.Path, "online", &cpu.Online); err != nil {
		cpu.Online = true
	}

	return nil
}

// Discovers topology information for a node.
func (node *NodeInfo) Discover() error {
	var err error

	if _, err = getSysfsEntry(node.Path, "distance", &node.Distance); err != nil {
		return err
	}
	if _, err = getSysfsEntry(node.Path, "cpulist", &node.Cpus); err != nil {
		return err
	}

	return nil
}

// CpuCount returns the number of CPUs in the node.
func (node *NodeInfo) CpuCount() int {
	return len(node.Cpus)
}

// Cpus returns the ids of CPUs in the node.
func (node *NodeInfo) CpuIds() []int {
	return node.Cpus
}

// CPUSet returns the ids of CPUs in the node as a CPUSet.
func (node *NodeInfo) CPUSet() cpuset.CPUSet {
	return cpuset.NewCPUSet(node.Cpus...)
}

// CpuCount returns the number of CPUs in the package.
func (pkg *PackageInfo) CpuCount() int {
	return len(pkg.Cpus)
}

// Cpus returns the ids of CPUs in the package.
func (pkg *PackageInfo) CpuIds() []int {
	return pkg.Cpus
}

// CPUSet returns the ods of CPUs in the package as a CPUSet.
func (pkg *PackageInfo) CPUSet() cpuset.CPUSet {
	return cpuset.NewCPUSet(pkg.Cpus...)
}

// CpuCount returns the number of CPU cores.
func (cpu *CpuInfo) CpuCount() int {
	return len(cpu.Threads)
}

// Cpus returns the ids of all hyperthreads.
func (cpu *CpuInfo) CpuIds() []int {
	return cpu.Threads
}

// CPUSet returns the hyperthread cores as a CPUSet.
func (cpu *CpuInfo) CPUSet() cpuset.CPUSet {
	return cpuset.NewCPUSet(cpu.Threads...)
}

// getNameEnumeration digs out the numeric id of the name of an enumerated object.
func getNameEnumeration(name string) int {
	name = filepath.Base(name)
	idx := strings.IndexAny(name, "0123456789")
	if idx < 0 {
		return -1
	}
	id, err := strconv.Atoi(name[idx:])
	if err != nil {
		return -1
	}

	return id
}

// getSysfsEntry reads, parses and converts the given entry to a caller-provided type/format.
func getSysfsEntry(base, path string, ptr interface{}) (string, error) {
	var entry string
	var err error

	if blob, err := ioutil.ReadFile(filepath.Join(base, path)); err != nil {
		return "", err
	} else {
		entry = strings.Trim(string(blob), "\n")
	}

	if ptr == interface{}(nil) {
		return entry, nil
	}

	switch ptr.(type) {
	case *int:
		intp := ptr.(*int)
		if *intp, err = strconv.Atoi(entry); err != nil {
			return "", err
		}
		return entry, nil

	case *string:
		strp := ptr.(*string)
		*strp = entry
		return entry, nil

	case *bool:
		boolp := ptr.(*bool)
		switch entry {
		case "0":
			fallthrough
		case "false":
			*boolp = false
		case "1":
			fallthrough
		case "true":
			*boolp = true
		default:
			return "", fmt.Errorf("can't interpret sysfs value '%s' (%s) as boolean", entry, path)
		}
		return entry, nil

	case *[]string:
		var sep string
		strsp := ptr.(*[]string)
		if strings.IndexAny(entry, ",") > -1 {
			sep = ","
		} else {
			sep = " "
		}
		*strsp = strings.Split(entry, sep)
		return entry, nil

	case *[]int:
		var sep string
		var val int
		intsp := ptr.(*[]int)
		if strings.IndexAny(entry, ",") > -1 {
			sep = ","
		} else {
			sep = " "
		}
		*intsp = []int{}
		for _, str := range strings.Split(entry, sep) {
			rng := strings.Split(str, "-")
			if len(rng) == 2 {
				var beg, end int

				if beg, err = strconv.Atoi(rng[0]); err != nil {
					return "", err
				}
				if end, err = strconv.Atoi(rng[1]); err != nil {
					return "", err
				}
				for val := beg; val <= end; val++ {
					*intsp = append(*intsp, val)
				}
			} else {
				if val, err = strconv.Atoi(rng[0]); err != nil {
					return "", err
				}
				*intsp = append(*intsp, val)
			}
		}
		return entry, nil

	default:
		return "", fmt.Errorf("unsupported sysfs entry type %T", ptr)
	}
}

//
// fake/mock SystemInfo for testing
//

func mockPackages(s *SystemInfo) error {
	pkgCnt := len(s.Packages)
	nodesPerPkg := len(s.Nodes) / pkgCnt
	cpusPerPkg := len(s.Cpus) / pkgCnt

	for id := 0; id < len(s.Packages); id++ {
		pkg := s.Packages[id]
		pkg.Id = id
		pkg.Cpus = make([]int, cpusPerPkg)
		pkg.Nodes = make([]int, nodesPerPkg)

		for i := 0; i < cpusPerPkg; i++ {
			pkg.Cpus[i] = id * cpusPerPkg + i
		}

		for i := 0; i < nodesPerPkg; i++ {
			pkg.Nodes[i] = id * nodesPerPkg + i
		}
	}

	return nil
}

func mockSiblingCores(minCore, cpusPerPkg int) []int {
	cores := make([]int, cpusPerPkg)
	for i := 0; i < cpusPerPkg; i++ {
		cores[i] = minCore + i
	}
	return cores
}

func mockSiblingThreads(id, threadsPerCore, threadDiff int) []int {
	threads := make([]int, threadsPerCore)
	for i := 0; i < threadsPerCore; i++ {
		threads[i] = id + i * threadDiff
	}
	return threads
}

func mockCpus(s *SystemInfo, threadsPerCore int) error {
	pkgCnt := len(s.Packages)
	cpusPerPkg := len(s.Cpus) / pkgCnt

	for id := 0; id < len(s.Cpus); id++ {
		if id != 0 && s.Cpus[id].Id != 0 {
			continue
		}

		pkg := id / cpusPerPkg
		minCore := pkg * cpusPerPkg
		threadDiff := cpusPerPkg / threadsPerCore

		cores := mockSiblingCores(minCore, cpusPerPkg)
		threads := mockSiblingThreads(id, threadsPerCore, threadDiff)
		for _, tid := range threads {
			s.Cpus[tid] = &CpuInfo{
				Id: tid,
				PackageId: pkg,
				NodeId: -1,
				Cores: cores,
				Threads: threads,
				MinFreq: 1 * 1000 * 1000,
				MaxFreq: 4 * 1000 * 1000,
				Online: true,
			}
		}
	}

	return nil
}

func nodePackage(s *SystemInfo, n int) int {
	for _, pkg := range s.Packages {
		for _, node := range pkg.Nodes {
			if node == n {
				return pkg.Id
			}
		}
	}
	return -1
}

func sameSNC(s *SystemInfo, n1, n2 int) bool {
	pkg1 := nodePackage(s, n1)
	pkg2 := nodePackage(s, n2)
	return pkg1 == pkg2 && pkg1 != -1
}

func mockNodes(s *SystemInfo) error {
	pkgCnt := len(s.Packages)
	nodesPerPkg := len(s.Nodes) / pkgCnt

	i := 0
	for _, pkg := range s.Packages {
		for _, id := range pkg.Cpus {
			cpu := s.Cpus[id]
			for _, tid := range cpu.Threads {
				thread := s.Cpus[tid]
				nodeId := pkg.Nodes[i % nodesPerPkg]
				thread.NodeId = nodeId
				node := s.Nodes[nodeId]

				if node.Distance == nil {
					node.Distance = make([]int, len(s.Nodes))
					for n, _ := range s.Nodes {
						if n == nodeId {
							node.Distance[n] = 10
						} else {
							if sameSNC(s, n, nodeId) {
								node.Distance[n] = 11
							} else {
								node.Distance[n] = 20
							}
						}
					}
				}

				if tid != id {
					continue
				}

				if node.Cpus == nil {
					node.Cpus = []int{tid}
				} else {
					node.Cpus = append(node.Cpus, tid)
				}
			}
			i++
		}
	}

	return nil
}

func mockSystemInfo(pkgCnt, nodesPerPkg, cpusPerPkg, threadsPerCore int, offln string) (*SystemInfo, error) {
	if nodesPerPkg <= 0 {
		nodesPerPkg = 1
	}

	s := &SystemInfo{
		Path: "/mock/system/info",
		Cpus: make(map[int]*CpuInfo),
		Nodes: make(map[int]*NodeInfo),
		Packages: make(map[int]*PackageInfo),
		Offline: cpuset.MustParse(offln),
	}

	for id := 0; id < pkgCnt; id++ {
		s.Packages[id] = &PackageInfo{}
	}

	for id := 0; id < pkgCnt * cpusPerPkg * threadsPerCore; id++ {
		s.Cpus[id] = &CpuInfo{ Path: fmt.Sprintf("/mock/cpu%d", id) }
	}

	for id := 0; id < pkgCnt * nodesPerPkg; id++ {
		s.Nodes[id] = &NodeInfo{ Path: fmt.Sprintf("/mock/node%d", id), Id: id }
	}

	if err := mockPackages(s); err != nil {
		return nil, err
	}
	if err := mockCpus(s, threadsPerCore); err != nil {
		return nil, err
	}
	if err := mockNodes(s); err != nil {
		return nil, err
	}

	// s.Dump()
	sysinfo = s
	return mockCheckSystemInfo(sysinfo)
}

func mockCheckSystemInfo(s *SystemInfo) (*SystemInfo, error) {
	var err error

	pkgCnt := len(s.Packages)
	threadsPerCore := len(s.Cpus[0].Threads)
	nodesPerPkg := len(s.Nodes) / pkgCnt
	cpusPerPkg := len(s.Cpus) / threadsPerCore / pkgCnt

	config := fmt.Sprintf("%d/%d/%d/%d", pkgCnt, nodesPerPkg, cpusPerPkg, threadsPerCore)
	for _, cpu := range s.Cpus {
		for _, tid := range cpu.Threads {
			thread := s.Cpus[tid]
			if thread.NodeId == cpu.NodeId {
				continue
			}

			if cpu.Threads[0] != cpu.Id { // only print once per HT-group
				continue
			}

			if err == nil {
				err = fmt.Errorf("broken node/HT configuration for %s", config)
			}

			if config != "" {
				fmt.Printf("* config: %s\n", config)
				config = ""
			}

			fmt.Printf("error: HT threads #%d, #%d in different nodes #%d, #%d\n",
				cpu.Id, thread.Id, cpu.NodeId, thread.NodeId)
			fmt.Printf("  %+v\n", *cpu)
			fmt.Printf("  %+v\n", *thread)
		}
	}

	if err != nil {
		return nil, err
	}

	return s, nil
}
