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
	cpus map[int]*CpuInfo         // CPU core information
	Nodes map[int]*NodeInfo       // NUMA node information
	Packages map[int]*PackageInfo // physical package information
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
}

// NodeInfo provides infromation about a NUMA node.
type NodeInfo struct {
	Path string            // sysfs path for this node
	Id int                 // node id
	Distance []int         // distance from other nodes
	cpus []int             // cores in this node
}

// PackageInfo provides information about a single physical package.
type PackageInfo struct {
	Id int                 // physical package id
	cpus []int             // cores in this node
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
	s.cpus = make(map[int]*CpuInfo)
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
		s.cpus[id] = cpu
	}

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

	for _, cpu = range s.cpus {
		if pkg, ok = s.Packages[cpu.PackageId]; ok {
			pkg.cpus = append(pkg.cpus, cpu.Id)
		} else {
			pkg = &PackageInfo{
				Id: cpu.PackageId,
				cpus: []int{cpu.Id},
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
	return len(s.cpus)
}

// Cpus returns gathered info for all the CPUs in the system.
func (s *SystemInfo) Cpus() map[int]*CpuInfo {
	return s.cpus
}

// CPUSet returns the ids of all CPUs in the system as a CPUSet.
func (s *SystemInfo) CPUSet() cpuset.CPUSet {
	b := cpuset.NewBuilder()
	for id, _ := range s.cpus {
		b.Add(id)
	}
	return b.Result()
}

// PackageCount returns the number of physical packages in the system.
func (s *SystemInfo) PackageCount() int {
	return len(s.Packages)
}

// PackageCpuCount returns the number of CPUs in the given physical package.
func (s *SystemInfo) PackageCpuCount(pkg int) int {
	if pkg, ok := s.Packages[pkg]; ok {
		return len(pkg.cpus)
	} else {
		return 0
	}
}

// PackageCpus returns the ids of the CPUs in the given package.
func (s *SystemInfo) PackageCpus (pkgId int) []int {
	if pkg, ok := s.Packages[pkgId]; ok {
		return pkg.cpus
	} else {
		return []int{}
	}
}

// PackageCPUSet returns the CPUs in the given package as a CPUSet.
func (s *SystemInfo) PackageCPUSet(pkgId int) cpuset.CPUSet {
	if pkg, ok := s.Packages[pkgId]; ok {
		return cpuset.NewCPUSet(pkg.cpus...)
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
		return len(node.cpus)
	} else {
		return 0
	}
}

// NodeCpus returns the ids of the CPUs local to the given node.
func (s *SystemInfo) NodeCpus(nodeId int) []int {
	if node, ok := s.Nodes[nodeId]; ok {
		return node.cpus
	} else {
		return []int{}
	}
}

// NodeCPUSet returns the CPUs local to the given node as a CPUSet.
func (s *SystemInfo) NodeCPUSet(nodeId int) cpuset.CPUSet {
	if node, ok := s.Nodes[nodeId]; ok {
		return cpuset.NewCPUSet(node.cpus...)
	} else {
		return cpuset.NewCPUSet()
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

	return nil
}

// ThreadCpus returns the ids of all hyperthreads. XXX TODO: remove this (== .Cpus())
func (cpu *CpuInfo) ThreadCpus() []int {
	return cpu.Threads
}

// ThreadCPUSet returns the ids of all hyperthreads as a CPUSet. XXX TODO: remove this (== .CPUSet())
func (cpu *CpuInfo) ThreadCPUSet() cpuset.CPUSet {
	return cpuset.NewCPUSet(cpu.Threads...)
}

// Discovers topology information for a node.
func (node *NodeInfo) Discover() error {
	var err error

	if _, err = getSysfsEntry(node.Path, "distance", &node.Distance); err != nil {
		return err
	}
	if _, err = getSysfsEntry(node.Path, "cpulist", &node.cpus); err != nil {
		return err
	}

	return nil
}

// CpuCount returns the number of CPUs in the node.
func (node *NodeInfo) CpuCount() int {
	return len(node.cpus)
}

// Cpus returns the ids of CPUs in the node.
func (node *NodeInfo) Cpus() []int {
	return node.cpus
}

// CPUSet returns the ids of CPUs in the node as a CPUSet.
func (node *NodeInfo) CPUSet() cpuset.CPUSet {
	return cpuset.NewCPUSet(node.cpus...)
}

// CpuCount returns the number of CPUs in the package.
func (pkg *PackageInfo) CpuCount() int {
	return len(pkg.cpus)
}

// Cpus returns the ids of CPUs in the package.
func (pkg *PackageInfo) Cpus() []int {
	return pkg.cpus
}

// CPUSet returns the ods of CPUs in the package as a CPUSet.
func (pkg *PackageInfo) CPUSet() cpuset.CPUSet {
	return cpuset.NewCPUSet(pkg.cpus...)
}

// CpuCount returns the number of CPU cores.
func (cpu *CpuInfo) CpuCount() int {
	return len(cpu.Threads)
}

// Cpus returns the ids of all hyperthreads.
func (cpu *CpuInfo) Cpus() []int {
	return cpu.Threads
}

// CPUSet returns the hyperthread cores as a CPUSet.
func (cpu *CpuInfo) CPUSet() cpuset.CPUSet {
	return cpuset.NewCPUSet(cpu.Threads...)
}

// getNameEnumeration digs out the numeric id of the name of an enumerated object.
func getNameEnumeration(name string) int {
	idx := strings.LastIndexAny(name, "0123456789")
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
