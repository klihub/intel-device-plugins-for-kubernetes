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
	"io/ioutil"
	"path/filepath"
	"encoding/json"
	"github.com/fsnotify/fsnotify"
)

const (
	// node to type map file name
	nodeTypeMap = "nodemap"
	// default node configuration file name
	defaultType = "type.default"
)

// Configuration change notification callback type.
type ConfigNotifyFunc func ()

// Node (policy) configuration picker/watcher.
type ConfigPicker interface {
	PickConfig(nodeName string) (string, error)
	WatchConfig(notifyfn ConfigNotifyFunc) error
	StopWatch()
}

// Node configuration picker implementation.
type configPicker struct {
	cfgDir string            // directory with configuration data
	stopCh chan struct{}     // channel to stop watcher
}

// Make sure configPicker implements the ConfigPicker interface.
var _ ConfigPicker = &configPicker{}

// Create a new node configuration picker.
func NewConfigPicker(cfgDir string) ConfigPicker {
	return &configPicker{
		cfgDir: cfgDir,
	}
}

// Pick the node-specific configuration file if it exists.
func (p *configPicker) nodeConfig(nodeName string) (string, error) {
	path := filepath.Join(p.cfgDir, "node." + nodeName)
	log.Info("trying node-specific configuration %s...", path)

	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}

// Pick configuration file for a node based on a node map.
func (p *configPicker) mappedConfig(nodeName string) (string, error) {
	typemap := make(map[string]string)
	mappath := filepath.Join(p.cfgDir, nodeTypeMap)

	log.Info("trying configuration for %s from %s...", nodeName, mappath)

	if _, err := os.Stat(mappath); err != nil {
		return "", err
	}
	buf, err := ioutil.ReadFile(mappath)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(buf, &typemap); err != nil {
		return "", err
	}

	nodetype, found := typemap[nodeName]
	if !found {
		return "", fmt.Errorf("no type specified for node %s", nodeName)
	}

	return filepath.Join(p.cfgDir, "type." + nodetype), nil
}

// Pick the default configuration if it exists.
func (p *configPicker) defaultConfig() (string, error) {
	path := filepath.Join(p.cfgDir, defaultType)
	log.Info("trying default configuration %s...", path)

	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}

// Pick the configuration file for the given node name.
func (p *configPicker) PickConfig(nodeName string) (string, error) {
	log.Info("picking configuration for node %s from %s", nodeName, p.cfgDir)

	if path, err := p.nodeConfig(nodeName); err == nil {
		return path, nil
	}

	if path, err := p.mappedConfig(nodeName); err == nil {
		return path, nil
	}

	return p.defaultConfig()
}

// Watch the configuration data for changes.
func (p *configPicker) WatchConfig(notifyfn ConfigNotifyFunc) error {
	log.Info("setting configuration watch for %s", p.cfgDir)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %v", err)
	}

	if err := w.Add(filepath.Dir(p.cfgDir)); err != nil {
		w.Close()
		return fmt.Errorf("failed to add %s to file watcher: %v", filepath.Dir(p.cfgDir), err)
	}

	p.stopCh = make(chan struct{})

	go func () {
		for {
			select {
			case evt := <-w.Events:
				log.Info("event %v for config file %s", evt.Op, evt.Name)
				if evt.Name == p.cfgDir {
					if evt.Op == fsnotify.Create {
						notifyfn()
					}
				}

			case err := <-w.Errors:
				log.Info("configuration watch error %v", err)

			case _ = <-p.stopCh:
				log.Info("stopping configuration watch for %s", p.cfgDir)
				w.Close()
				return
			}
		}
	}()

	return nil
}

// Stop watching configuration changes.
func (p *configPicker) StopWatch() {
	if p.stopCh == nil {
		return
	}

	log.Info("shutting down configuration watch for %s", p.cfgDir)
	p.stopCh <- struct{}{}
	close(p.stopCh)
	p.stopCh = nil
}
