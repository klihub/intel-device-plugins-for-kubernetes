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

type ProcFs interface {
	KernelCmdline
}

type KernelCmdline interface {
	// Get the value of the given kernel commandline option.
	KernelOption(option string) (string, bool)
	// Check if the given flag is set on the kernel commandline.
	KernelFlag(flag string) bool
}

type kernelCmdline struct {
	cmdline string
	options map[string]string
	flags map[string]struct{}
}

func (k *kernelCmdline) KernelOption(option string) (string, bool) {
	return "", false
}

func (k *kernelCmdline) KernelFlag(flag string) bool {
	return false
}
