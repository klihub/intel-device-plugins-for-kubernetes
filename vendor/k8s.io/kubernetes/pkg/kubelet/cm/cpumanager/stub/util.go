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
	cmdlinePath = "/proc/cmdline"
	systemPath = "/sys/devices/system"
	isolatedCpus = "isolcpus"
)

// Kernel command line
type KernelCmdline struct {
	Cmdline string            // full command line
	Options map[string]string // 'name=value' options
	Flags   []string          // 'flag' options
}

// Read and parse the kernel commandline, extract options and flags.
func (kcl *KernelCmdline) Parse(path string) error {
	if path == "" {
		path = cmdlinePath
	}
	if kcl.Options == nil {
		kcl.Options = make(map[string]string)
	}
	if kcl.Flags == nil {
		kcl.Flags = []string{}
	}

	if buf, err := ioutil.ReadFile(path); err != nil {
		return err
	} else {
		kcl.Cmdline = strings.Trim(string(buf), " \n")
	}

	for _, opt := range strings.Split(kcl.Cmdline, " ") {
		if opt = strings.Trim(opt, " "); opt == "" {
			continue
		}
		if kv := strings.SplitN(opt, "=", 2); len(kv) == 2 {
			kcl.Options[kv[0]] = kv[1]
		} else {
			kcl.Flags = append(kcl.Flags, kv[0])
		}
	}

	return nil
}

// Parse the kernel commandline if we haven't done so yet.
func (kcl *KernelCmdline) Check() error {
	if kcl.Cmdline != "" {
		return nil
	}
	return kcl.Parse("")
}

// Check if the kernel commandline has the given option.
func (kcl *KernelCmdline) HasOption(option string) bool {
	kcl.Check()
	_, found := kcl.Options[option]
	return found
}

// Check if the kernel commandline has the given flag.
func (kcl *KernelCmdline) HasFlag(flag string) bool {
	kcl.Check()
	for _, f := range kcl.Flags {
		if f == flag {
			return true
		}
	}
	return false
}

// Get the value of the given kernel commandline option.
func (kcl *KernelCmdline) Option(option string) string {
	kcl.Check()
	if value, found := kcl.Options[option]; found {
		return value
	} else {
		return ""
	}
}

// Get the list of isolated CPUs.
func (kcl *KernelCmdline) IsolatedCPUs() ([]int, error) {
	if err := kcl.Check(); err != nil {
		return []int{}, err
	}

	cpulist, ok := kcl.Options[isolatedCpus]
	if !ok {
		return []int{}, nil
	}

	cpus := []int{}
	for _, cpustr := range strings.Split(cpulist, ",") {
		if cpu, err := strconv.ParseUint(cpustr, 10, 0); err != nil {
			return []int{}, err
		} else {
			cpus = append(cpus, int(cpu))
		}
	}

	return cpus, nil
}

// Get the list of isolated CPUs as a CPUSet.
func (kcl *KernelCmdline) IsolatedCPUSet() (cpuset.CPUSet, error) {
	if cpus, err := kcl.IsolatedCPUs(); err != nil {
		return cpuset.NewCPUSet(), err
	} else {
		return cpuset.NewCPUSet(cpus...), nil
	}
}


//
// hardware topology discovery
//

type MachineInfo struct {
	Path string
	Cpus map[int]*CpuInfo
	Nodes map[int]*NodeInfo
}

// CpuInfo provides topology information about a single CPU core.
type CpuInfo struct {
	Path string     // sysfs path for this CPU
	Id int          // CPU id
	NodeId int      // NUMA node id
	PackageId int   // physical package id
	Cores []int     // cores in the same package
	Threads []int   // hyperthreads in the same core
}

// NodeInfo provides topology information about single NUMA node.
type NodeInfo struct {
	Path string     // sysfs path for this node
	Id int          // node id
	Distance []int  // distance from other nodes
	Cpus []int      // cores in this node
}


// Collect and parse machine topology information from sysfs.
func (m *MachineInfo) Discover(dir string) error {
	if m.Path != "" {
		return nil
	}
	if dir == "" {
		dir = systemPath
	}

	m.Path = dir
	m.Cpus = make(map[int]*CpuInfo)
	m.Nodes = make(map[int]*NodeInfo)

	if err := m.DiscoverCpus(filepath.Join(dir, "cpu")); err != nil {
		return err
	}
	if err := m.DiscoverNodes(filepath.Join(dir, "node")); err != nil {
		return err
	}

	return nil
}

// Discover CPU topology information from sysfs.
func (m *MachineInfo) DiscoverCpus(cpuDir string) error {
	var entries []os.FileInfo
	var err error

	if entries, err = ioutil.ReadDir(cpuDir); err != nil {
		return err
	}
	for _, entry := range entries {
		var name string
		var id int

		if name = entry.Name(); name[0:3] != "cpu" {
			continue
		}
		if id = getEnumId(name); id < 0 {
			continue
		}

		cpu := &CpuInfo{ Path: filepath.Join(cpuDir, name), Id: id }
		m.Cpus[id] = cpu
		if err = cpu.Discover(); err != nil {
			return err
		}
	}

	return nil
}

// Discover NUMA topology information from sysfs.
func (m *MachineInfo) DiscoverNodes(nodeDir string) error {
	var entries []os.FileInfo
	var err error

	if entries, err = ioutil.ReadDir(nodeDir); err != nil {
		return err
	}
	for _, entry := range entries {
		var name string
		var id int

		if name = entry.Name(); name[0:4] != "node" {
			continue
		}
		if id = getEnumId(name); id < 0 {
			continue
		}

		node := &NodeInfo{ Path: filepath.Join(nodeDir, name), Id: id }
		m.Nodes[id] = node
		if err = node.Discover(); err != nil {
			return err
		}
	}

	return nil
}

// Discover machine topology information, if necessary.
func (m *MachineInfo) check() error {
	if m.Path != "" {
		return nil
	} else {
		return m.Discover("")
	}
}

// Get the CPUs for the given physical package.
func (m *MachineInfo) PackageCPUs(pkg int) []int {
	if m.check() != nil {
		return []int{}
	}

	cpus := []int{}
	for id, cpu := range m.Cpus {
		if cpu.PackageId == pkg {
			cpus = append(cpus, id)
		}
	}

	return cpus
}

// Get the CPUSet for the given physical package.
func (m *MachineInfo) PackageCPUSet(pkg int) cpuset.CPUSet {
	if m.check() != nil {
		return cpuset.NewCPUSet()
	}

	b := cpuset.NewBuilder()
	for id, cpu := range m.Cpus {
		if cpu.PackageId == pkg {
			b.Add(id)
		}
	}
	return b.Result()
}

// Get the CPUs for the given NUMA node.
func (m *MachineInfo) NodeCPUs(node int) []int {
	if m.check() != nil {
		return []int{}
	}

	cpus := []int{}
	for id, cpu := range m.Cpus {
		if cpu.NodeId == node {
			cpus = append(cpus, id)
		}
	}

	return cpus
}

// Get the CPUSet for the given NUMA node.
func (m *MachineInfo) NodeCPUSet(node int) cpuset.CPUSet {
	if m.check() != nil {
		return cpuset.NewCPUSet()
	}

	b := cpuset.NewBuilder()
	for id, cpu := range m.Cpus {
		if cpu.NodeId == node {
			b.Add(id)
		}
	}
	return b.Result()
}

// Discover topology for a CPU.
func (cpu *CpuInfo) Discover() error {
	var nodes []string
	var err error

	if nodes, err = filepath.Glob(filepath.Join(cpu.Path, "node[0-9]*")); err != nil {
		return err
	}
	if len(nodes) != 1 {
		return fmt.Errorf("failed discover node for CPU#%d", cpu.Id)
	}

	if cpu.NodeId = getEnumId(nodes[0]); cpu.NodeId < 0 {
		return fmt.Errorf("failed to discover node for CPU#%d", cpu.Id)

	}
	if _, err = getEntry(cpu.Path, "topology/physical_package_id", &cpu.PackageId); err != nil {
		return err
	}
	if _, err = getEntry(cpu.Path, "topology/core_siblings_list", &cpu.Cores); err != nil {
		return err
	}
	if _, err  = getEntry(cpu.Path, "topology/thread_siblings_list", &cpu.Threads); err != nil {
		return err
	}

	return nil
}

// Discover topology information for a node.
func (node *NodeInfo) Discover() error {
	var err error

	if _, err = getEntry(node.Path, "distance", &node.Distance); err != nil {
		return err
	}
	if _, err = getEntry(node.Path, "cpulist", &node.Cpus); err != nil {
		return err
	}

	return nil
}

// Read, parse, and convert the given entry to an entry-specific type/format.
func getEntry(base, path string, ptr interface{}) (string, error) {
	var entry string
	var err error

	if blob, err := ioutil.ReadFile(filepath.Join(base, path)); err != nil {
		return "", err
	} else {
		entry = strings.Trim(string(blob), "\n")

		if ptr == interface{}(nil) {
			return entry, nil
		}
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
		var str, sep string
		var val int
		intsp := ptr.(*[]int)
		if strings.IndexAny(entry, ",") > -1 {
			sep = ","
		} else {
			sep = " "
		}
		strs := strings.Split(entry, sep)
		*intsp = []int{}
		for _, str = range strs {
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
		return "", fmt.Errorf("unsupported entry type %T", ptr)
	}
}

// Get the enumerated id from a CPU or node name.
func getEnumId(str string) int {
	idx := strings.LastIndexAny(str, "0123456789")
	if idx < 0 {
		return -1
	}
	id, err := strconv.Atoi(str[idx:])
	if err != nil {
		return -1
	}

	return id
}

