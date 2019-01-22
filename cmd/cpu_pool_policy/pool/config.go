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

package pool

import (
	"fmt"
	"strings"
	"strconv"
	"io/ioutil"
	"encoding/json"

	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/stub"
)

const (
	wildcardCpu   = "*"       // wildcard cpuset, used to claim leftover CPUs
	claimLeftover = -1        // wildcard CPU count
)

// Configuration for this node, as read from the filesystem/ConfigMap.
type configFile map[string]configFileEntry

// Entry for a single CPU pool in the configuration file.
type configFileEntry struct {
	CpuCount   int           `json:"cpucount,omitempty"`  // CPU count, if CPUs auto-picked
	Cpus       string        `json:"cpuset,omitempty"`    // CPUs, if explicitly set
	Isolated   bool          `json:"isolated,omitempty"`  // use isolated CPUs
	DisableHT  bool          `json:"disableHT,omitempty"` // take HT siblings offline
	MinFreq    string        `json:"minFreq,omitempty"`   // allowed min. CPU frequency, if overridden
	MaxFreq    string        `json:"maxFreq,omitempty"`   // allowed max. CPU frequency, if overridden
}

// Runtime configuration for this node, with one entry per CPU pool.
type NodeConfig map[string]*Config

// Runtime configuration for a single CPU pool.
type Config struct {
	CpuCount   int           `json:"size"`                // CPU count to allocate
	Cpus      *cpuset.CPUSet `json:"cpus,omitempty"`      // explicit CPUs to allocate, if given
	Isolated   bool          `json:"isolated,omitempty"`  // use isolated CPUs
	DisableHT  bool          `json:"disableHT,omitempty"` // take HT siblings offline
	MinFreq    uint64        `json:"minFreq,omitempty"`   // allowed lowest CPU frequency, if overridden
	MaxFreq    uint64        `json:"maxFreq,omitempty"`   // allowed lowest CPU frequency, if overridden
}

// cached isolated set of CPUs
var isolated *cpuset.CPUSet

// Get the set of kernel-isolated CPUs.
func isolatedCPUSet() cpuset.CPUSet {
	if isolated != nil {
		return *isolated
	}

	kcl, err := stub.GetKernelCmdline()
	if err != nil {
		panic(fmt.Sprintf("failed to parse kernel command line: %v", err))
	}

	cset, err := kcl.IsolatedCPUSet()
	if err != nil {
		panic(fmt.Sprintf("failed to get isolated cpus: %v", err))
	}

	isolated = &cset
	return cset
}

// Create default CPU pool set configuration.
func DefaultNodeConfig(numReservedCPUs int) (NodeConfig, error) {
	cfg := make(NodeConfig)

	cfg.configure(ReservedPool, configFileEntry{CpuCount: numReservedCPUs})
	cfg.configure(DefaultPool, configFileEntry{Cpus: wildcardCpu})

	return cfg, nil
}

// Parse the given configuration file.
func ParseNodeConfig(path string, numReservedCPUs int) (NodeConfig, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return NodeConfig{}, configError("%v", err)
	}

	file := make(configFile)
	if err = json.Unmarshal(buf, &file); err != nil {
		return NodeConfig{}, configError("%v", err)
	}
	
	cfg := make(NodeConfig)
	if err = cfg.parseRequiringExplicitCpus(file, numReservedCPUs); err != nil {
		return NodeConfig{}, err
	}

	return cfg, nil
}

// Dump node CPU pool configuration as a string.
func (cfg NodeConfig) String() string {
	if cfg == nil {
		return "{}"
	}

	str := "{ "
	t := " "
	for pool, pc := range cfg {
		str += fmt.Sprintf("%s%s: %s", t, pool, pc.String())
		t = ", "
	}
	str += "}"

	return str
}

// Parse the configuration file, requiring explicit cpusets (Cpus) for pools.
func (cfg NodeConfig) parseRequiringExplicitCpus(file configFile, numReservedCPUs int) error {
	cfg.configure(ReservedPool, configFileEntry{CpuCount: numReservedCPUs})

	for pool, entry := range file {
		if entry.Cpus == "" {
			if pool != ReservedPool {
				return configError("pool %s: must be configured by explicit cpuset", pool)
			}
		}

		if entry.Isolated {
			if pool == ReservedPool || pool == DefaultPool {
				return configError("pool %s: can't use isolated cpus", pool)
			}
		}

		if entry.DisableHT {
			if pool == ReservedPool || pool == DefaultPool {
				return configError("pool %s: cannot have HT-disabled cpus", pool)
			}
		}

		if err := cfg.configure(pool, entry); err != nil {
			return err
		}
	}

	if _, ok := cfg[DefaultPool]; !ok {
		cfg.configure(DefaultPool, configFileEntry{Cpus: wildcardCpu})
	}

	return nil
}

// Parse the configuration file, allowing pools to be configured by CpuCount.
func (cfg NodeConfig) parseAllowingCpuCount(file configFile, numReservedCPUs int) error {
	for pool, entry := range file {
		if entry.Isolated {
			if pool == ReservedPool || pool == DefaultPool {
				return configError("pool %s: can't use isolated cpus", pool)
			}
		}

		if entry.DisableHT {
			if pool == ReservedPool || pool == DefaultPool {
				return configError("pool %s: cannot have HT-disabled cpus", pool)
			}
		}

		if err := cfg.configure(pool, entry); err != nil {
			return err
		}
	}

	return nil
}

// Set up configuration entry for the given pool.
func (cfg NodeConfig) configure(pool string, entry configFileEntry) error {
	pc, ok := cfg[pool]
	if !ok {
		cfg[pool] = &Config{}
		pc = cfg[pool]
	}

	pc.Isolated = entry.Isolated
	pc.DisableHT = entry.DisableHT

	if frq, err := parseCpuFreq(entry.MinFreq); err != nil {
		return fmt.Errorf("pool %s: %v", pool, err)
	} else {
		pc.MinFreq = frq
	}
	if frq, err := parseCpuFreq(entry.MaxFreq); err != nil {
		return fmt.Errorf("pool %s: %v", pool, err)
	} else {
		pc.MaxFreq = frq
	}

	switch entry.Cpus {
	case "":
		pc.CpuCount = entry.CpuCount

	case wildcardCpu:
		pc.CpuCount = claimLeftover
		if pc.DisableHT {
			return configError("pool %s: pool claiming leftover CPUs can't be HT-free.", pool)
		}

	default:
		cset, err := cpuset.Parse(entry.Cpus)
		if err != nil {
			return configError("pool %s: invalid cpuset: %s", pool, pc.Cpus)
		}

		// check any isolation inconsistency
		if pc.Isolated {
			if !cset.IsSubsetOf(isolatedCPUSet()) {
				return configError("pool %s: CPUs #%s are not isolated", pool, cset.Difference(isolatedCPUSet()))
			}
		} else {
			if !cset.Intersection(isolatedCPUSet()).IsEmpty() {
				return configError("pool %s: CPUs #%s are isolated", pool, cset.Difference(isolatedCPUSet()))
			}
		}

		pc.Cpus = &cset
	}

	return nil
}

// Parse CPU frequency given as a string, with an optional base suffix (k, M, G).
func parseCpuFreq(freq string) (uint64, error) {
	if freq == "" {
		return uint64(0), nil
	}

	if idx := strings.LastIndexAny(freq, "kMG"); idx >= 0 {
		unit := map[string]uint64{
			"k": 1e3, "kHz": 1e3,
			"M": 1e6, "MHz": 1e6,
			"G": 1e9, "GHz": 1e9,
		}

		if base, ok := unit[freq[idx:]]; !ok {
			return 0, fmt.Errorf("invalid CPU frequency base in %s", freq)
		} else {
			val, err := strconv.ParseUint(freq[0:idx], 0, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid CPU frequency value %s", freq)
			}

			return val * base, nil
		}
	} else {
		val, err := strconv.ParseUint(freq, 0, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid CPU frequency %s", freq)
		}

		return val, nil
	}
}

// Return pool configuration as a string.
func (cfg *Config) String() string {
	if cfg == nil {
		return "<marked for removal>"
	}

	isolation := ""
	if cfg.Isolated {
		isolation = "isolated "
	}

	htconfig := ""
	if cfg.DisableHT {
		htconfig = " with HT disabled"
	}

	cpus := ""
	if cfg.Cpus != nil {
		cpus = fmt.Sprintf("CPUs #%s", cfg.Cpus.String())
	} else {
		if cfg.CpuCount != claimLeftover {
			cpus = fmt.Sprintf("any %d CPUs", cfg.CpuCount)
		} else {
			cpus = "leftover CPUs"
		}
	}

	freqs := ""
	if cfg.MinFreq != 0 || cfg.MaxFreq != 0 {
		freqs = fmt.Sprintf(", CPU freq.: %d-%d", cfg.MinFreq, cfg.MaxFreq)
	}

	return "<" + isolation + cpus + htconfig + freqs + ">"
}

// Format an error message related to configuration.
func configError(format string, args ...interface{}) error {
	return fmt.Errorf("invalid configuration: " + format, args...)
}
