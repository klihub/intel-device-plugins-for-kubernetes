// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sysfs

import (
	"sync"
)

const (
	defaultSysfsPath = "/sys"          // default sysfs mount path
)

// sysfs interface
type Sysfs interface {
}

// sysfs state
type sysfs struct {
	path string
}

// make sure sysfs implements the SysFs
var _ Sysfs = &sysfs{}

// sysfs singleton instance
var sys *sysfs
var once sync.Once

// sysfs mount path
var sysfsPath string = defaultSysfsPath


// Override the default sysfs mount path.
func SetSysfsPath(path string) string {
	oldPath := sysfsPath
	sysfsPath = path
	return oldPath
}

// Get the sysfs singleton instance.
func GetSysfs() Sysfs {
	once.Do(func () {
		sys = &sysfs{
			path: sysfsPath,
		}
	})

	return sys
}

