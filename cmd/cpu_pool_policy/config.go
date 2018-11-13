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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"github.com/fsnotify/fsnotify"
//	stub "k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/stub"
)

/*
const (
	// log message prefix
	logPrefix = "[cpu-policy/config]"
)

// our logger instance
var log = stub.NewLogger(logPrefix)
*/

// Configuration change notification callback type.
type ConfigNotifyFunc func(p ConfigPicker)

// Node (policy) configuration picker/watcher.
type ConfigPicker interface {
	PickConfig(nodeName string) (string, error)
	WatchConfig(notifyfn ConfigNotifyFunc) error
	StopWatch() error
}

// Node configuration picker implementation.
type configPicker struct {
	cfgDir string            // directory with configuration data
	stopCh chan struct{}     // channel to stop watcher
}

// configPicker should implement the ConfigPicker interface.
var _ ConfigPicker = &configPicker{}

// Create a new node configuration picker.
func NewConfigPicker(cfgDir string) ConfigPicker {
	return &configPicker{
		cfgDir: cfgDir,
	}
}

// Pick the configuration file for the given node name.
func (p *configPicker) PickConfig(nodeName string) (string, error) {
	log.Info("looking for configuration file for node %s", nodeName)

	path := filepath.Join(p.cfgDir, nodeName)

	if _, err := os.Stat(path); err != nil {
		return "", err
	}

	return path, nil
}

// Watch the configuration data for changes.
func (p *configPicker) WatchConfig(notifyfn ConfigNotifyFunc) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %+v", err)
	}

	if err := w.Add(filepath.Dir(p.cfgDir)); err != nil {
		w.Close()
		return fmt.Errorf("failed to add %s to file watcher: %+v", err)
	}

	p.stopCh = make(chan struct{})

	go func () {
		log.Info("*** watching for configuration changes in %s", p.cfgDir)
		for {
			select {
			case evt := <-w.Events:
				log.Info("*** configuration file event: %v for %s", evt.Op, evt.Name)
				if evt.Name == p.cfgDir {
					if evt.Op == fsnotify.Create {
						notifyfn(p)
					}
				}

			case err := <-w.Errors:
				log.Info("*** configuration file error: %+v", err)
				notifyfn(nil)

			case _ = <-p.stopCh:
				w.Close()
				return
			}
		}
	}()

	return nil
}

// Stop watching configuration changes.
func (p *configPicker) StopWatch() error {
	if p.stopCh == nil {
		return fmt.Errorf("configuration watcher not active")
	}

	log.Info("*** stopping configuration watched for %s", p.cfgDir)

	// notify watcher
	p.stopCh <- struct{}{}
	close(p.stopCh)
	p.stopCh = nil

	return nil
}
