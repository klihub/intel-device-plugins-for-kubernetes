package main

import (
	"github.com/intel/intel-device-plugins-for-kubernetes/pkg/sysfs"
)

func main() {
	sysfs.SetMountPath("/sys")

	sys := sysfs.GetSysFs()
	sys.DiscoverCpus()
}
