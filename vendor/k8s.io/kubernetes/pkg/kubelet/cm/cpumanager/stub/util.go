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
	"strings"
	"strconv"
	"io/ioutil"

	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
)

const (
	cmdlinePath = "/proc/cmdline"
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

// Check and parse if necessary the kernel commandline.
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
