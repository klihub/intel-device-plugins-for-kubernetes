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
	"io/ioutil"
	"encoding/json"

	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
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
	Cpus       string        `json:"cpus,omitempty"`      // CPUs, if explicitly set
	Isolate    bool          `json:"isolate,omitempty"`   // use isolated CPUs
	DisableHT  bool          `json:"disableHT,omitempty"` // take HT siblings offline
}

// Runtime configuration for this node, with one entry per CPU pool.
type NodeConfig map[string]*Config

// Runtime configuration for a single CPU pool.
type Config struct {
	CpuCount   int           `json:"size"`                // CPU count to allocate
	Cpus      *cpuset.CPUSet `json:"cpus,omitempty"`      // explicit CPUs to allocate, if given
	Isolate    bool          `json:"isolate,omitempty"`   // use isolated CPUs
	DisableHT  bool          `json:"disableHT,omitempty"` // take HT siblings offline
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
	if err = cfg.parseRequireExplicitCpus(file, numReservedCPUs); err != nil {
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
func (cfg NodeConfig) parseRequireExplicitCpus(file configFile, numReservedCPUs int) error {
	cfg.configure(ReservedPool, configFileEntry{CpuCount: numReservedCPUs})

	for pool, entry := range file {
		if entry.Cpus == "" {
			if pool != ReservedPool {
				return configError("pool %s must be configured by explicit cpuset", pool)
			}
		}

		if entry.Isolate {
			if pool == ReservedPool || pool == DefaultPool {
				return configError("pool %s can't use isolated cpus", pool)
			}
		}

		if entry.DisableHT {
			if pool == ReservedPool || pool == DefaultPool {
				return configError("pool %s cannot have HT-disabled cpus", pool)
			}
		}

		if err := cfg.configure(pool, entry); err != nil {
			return err
		}
	}

	return nil
}

// Parse the configuration file, allowing pools to be configured by CpuCount.
func (cfg NodeConfig) parseAllowCpuCount(file configFile, numReservedCPUs int) error {
	for pool, entry := range file {
		if entry.Isolate {
			if pool == ReservedPool || pool == DefaultPool {
				return configError("pool %s can't use isolated cpus", pool)
			}
		}

		if entry.DisableHT {
			if pool == ReservedPool || pool == DefaultPool {
				return configError("pool %s cannot have HT-disabled cpus", pool)
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

	pc.Isolate = entry.Isolate
	pc.DisableHT = entry.DisableHT

	switch entry.Cpus {
	case "":
		pc.CpuCount = entry.CpuCount
	case wildcardCpu:
		pc.CpuCount = claimLeftover
	default:
		cset, err := cpuset.Parse(entry.Cpus)
		if err != nil {
			return configError("invalid cpuset: %s", pc.Cpus)
		}
		pc.Cpus = &cset
	}

	return nil
}

// Dump pool configuration as a string.
func (cfg *Config) String() string {
	if cfg == nil {
		return "<marked for removal>"
	}
	
	isolation := ""
	if cfg.Isolate {
		isolation = "isolated "
	}

	htconfig := ""
	if cfg.DisableHT {
		htconfig = " with HT disabled"
	}

	cpus := ""
	if cfg.Cpus != nil {
		cpus = fmt.Sprintf("CPUs %s", cfg.Cpus.String())
	} else {
		if cfg.CpuCount != claimLeftover {
			cpus = fmt.Sprintf("any %d CPUs", cfg.CpuCount)
		} else {
			cpus = "leftover CPUs"
		}
	}

	return "<" + isolation + cpus + htconfig + ">"
}

// Format an error message for reading/parsing a configuation file.
func configError(format string, args ...interface{}) error {
	return fmt.Errorf("invalid configuration: " + format, args...)
}
