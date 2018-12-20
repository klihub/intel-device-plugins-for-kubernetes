// Copyright 2018 Intel Corporation. All Rights Reserved.
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

package stub

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc"

	"k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/topology"

	api "k8s.io/kubernetes/pkg/kubelet/apis/cpuplugin/v1draft1"
)

const (
	// log message prefix
	logPrefix = "[cpu-policy/stub] "
	// CPU plugin registration server timeout
	pluginTimeout = 10 * time.Second
	// CPUManager registration server timeout
	cpumgrTimeout = 10 * time.Second
)

// our logger instance
var log = NewLogger(logPrefix)

// CpuPolicy is the interface every pluggable CPU policy must implement.
//
// This interface is used by the CPU plugin stub to relay CPUManager
// requests (Start, AddContainer, RemoveContainer) and related responses
// back and forth between the externally running CPU policy plugin and
// the CPUManager via the plugin relay policy. The stub implementation
// of the policy State interface records changes the plugin makes to
// container resource assignments which is then relayed by the sub back
// to the CPUManager after every relayed request.
//
// The stub state provides a few extra methods which allow the plugin
// to declare policy/plugin-sepcific extended resources in addition to
// overriding the default native CPU resource capacity declared by the
// kubelet/cm, and to save policy/plugin-specific data within the
// kubelet CPUManager checkpoint data.
//
type CpuPolicy interface {
	// 'Construct'/initialize the policy plugin for being started.
	NewPolicy(topology *topology.CPUTopology, numReservedCPUs int) error
	// Return the well-known name of the policy.
	Name() string
	// Start the policy plugin, prepaing it for container requests.
	Start(s State) error
	// Add a pods container, allocating any necessary CPU for it.
	AddContainer(s State, p *v1.Pod, c *v1.Container, id string) error
	// Remove existing allocations for the given container.
	RemoveContainer(s State, id string)
}

//
// CpuPlugin is the public interface the CPU plugin stub implements.
//
// This interface, along with the NewCpuPlugin 'constructor' is used by
// the various CPU policy plugin implementations to set up, and start
// the CPU plugin instance.
//
type CpuPlugin interface {
	SetupAndServe() error
}

//
// cpuPlugin is the CPU plugin stub and implements the CpuPlugin interface.
//
// Maybe calling this pluginStub instead would be more appropriate...
//
type cpuPlugin struct {
	policy CpuPolicy        // CPU policy implementation
	state  stubState        // replicated/plugin stub state
	server *grpc.Server     // CPU plugin registration gRPC server
	vendor string           // vendor/extended resource namespace
}

// NewCpuPlugin create a CPU plugin stub instance for the given policy.
func NewCpuPlugin(policy CpuPolicy, vendor string) (CpuPlugin, error) {
	if !strings.Contains(vendor, ".") {
		return nil, fmt.Errorf("invalid vendor string '%s', should be a domain name", vendor)
	}

	return &cpuPlugin{
		policy:     policy,
		vendor:     vendor,
	}, nil
}

// Set up and start the CPU plugin, serve requests.
func (p *cpuPlugin) SetupAndServe() error {
	for {
		if err := p.SetupCpuPluginServer(); err != nil {
			return err
		}

		if err := p.RegisterWithCPUManager(); err != nil {
			return err
		}

		if err := watchFileRemoval(p.cpuPluginSocket()); err != nil {
			return err
		}

		p.server.Stop()
	}
}

// Relay configuration request to CPU policy.
func (p *cpuPlugin) Start(ctx context.Context, req *api.StartRequest) (*api.StartResponse, error) {
	topology := CoreCPUTopology(req.Topology)
	numReservedCPUs := int(req.NumReservedCPUs)
	p.state = newStubState(req.State)

	if err := p.policy.NewPolicy(&topology, numReservedCPUs); err != nil {
		return nil, err
	}

	if err := p.policy.Start(&p.state); err != nil {
		return nil, err
	}

	return &api.StartResponse{
		Resources: p.state.ResourceChanges(true),
		State:     p.state.StateChanges(),
	}, nil
}

// Relay AddContainer request to CPU policy.
func (p *cpuPlugin) AddContainer(ctx context.Context, req *api.AddContainerRequest) (*api.AddContainerResponse, error) {
	pod := CorePod(req.Pod)
	container := CoreContainer(req.Container)
	id := req.Id

	p.state.Reset()
	if err := p.policy.AddContainer(&p.state, &pod, &container, id); err != nil {
		return nil, err
	}

	return &api.AddContainerResponse{
		Hints:     p.state.ContainerChanges(),
		Resources: p.state.ResourceChanges(false),
		State:     p.state.StateChanges(),
	}, nil
}

// Relay RemoveContainer request to CPU policy.
func (p *cpuPlugin) RemoveContainer(ctx context.Context, req *api.RemoveContainerRequest) (*api.RemoveContainerResponse, error) {
	id := req.Id

	p.state.Reset()
	p.policy.RemoveContainer(&p.state, id)

	return &api.RemoveContainerResponse{
		Hints:     p.state.ContainerChanges(),
		Resources: p.state.ResourceChanges(false),
		State:     p.state.StateChanges(),
	}, nil
}

// Start the (unsolicited) container update event loop.
func (p *cpuPlugin) WatchContainerUpdates(emtpy *api.Empty, srv api.CpuPlugin_WatchContainerUpdatesServer) error {
	log.Info("starting container update event forwarding loop")

	//
	// Notes:
	//   Curently we just sit tight and dummy here. The policy relay plugin merely uses this
	//   streaming interface to detect if/when the plugin goes down. It does not do anything
	//   with any actual events sent.
	//
	// TODO:
	//   Create a channel during plugin creation for passing here update events which are to
	//   be forwarded to the plugin relay on the kubelet side. Add a SendUpdateEvent function
	//   which can be used to push actual events through that channel here and to the relay.
	//

	for {
		time.Sleep(30 * time.Second)
	}

	return nil
}

// Set up the CPU plugin registration server.
func (p *cpuPlugin) SetupCpuPluginServer() error {
	// Check that another plugin instance is not running.
	socket := p.cpuPluginSocket()
	if serverActiveAt(socket) {
		return fmt.Errorf("can't set up CPU plugin, socket %s already in use", socket)
	}
	os.Remove(socket)

	// Create CPU plugin socket, start the registration server on it.
	lis, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("can create/listen on CPU plugin socket %s: %+v", socket, err)
	}

	p.server = grpc.NewServer()
	api.RegisterCpuPluginServer(p.server, p)
	go func() {
		log.Info("starting CPU plugin at %s", socket)
		p.server.Serve(lis)
	}()

	// Wait for the registration server to start up.
	if err := waitForServer(socket, pluginTimeout); err != nil {
		return fmt.Errorf("CPU plugin registration server timed out: %+v", err)
	}

	log.Info("CPU plugin registration server started");

	return nil
}

// Register CPU plugin with the CPUManager.
func (p *cpuPlugin) RegisterWithCPUManager() error {
	conn, err := grpc.Dial(p.cpuManagerSocket(), grpc.WithInsecure(),
		grpc.WithDialer(func (socket string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", socket, timeout)
		}))
	if err != nil {
		return fmt.Errorf("cannot connect to CPUManager: %+v", err)
	}
	defer conn.Close()

	client := api.NewRegistrationClient(conn)
	_, err = client.Register(context.Background(),
		&api.RegisterRequest{
			Version: api.Version,
			Name:    p.policy.Name(),
			Vendor:  p.vendor,
		})

	if err == nil {
		log.Info("registered with CPUManager")
	}

	return err
}

// Stop the CPU plugin.
func (p *cpuPlugin) Stop() {
	if p.server == nil {
		return
	}

	p.server.Stop()

	log.Info("stopped CPU plugin %s", p.policy.Name())
}

// Get the CPU Plugin registration server socket path.
func (p *cpuPlugin) cpuPluginSocket() string {
	return filepath.Join(api.CpuPluginPath, p.policy.Name()) + ".sock"
}

// Get the CPU Manager policy plugin registration socket path.
func (p *cpuPlugin) cpuManagerSocket() string {
	return api.CpuManagerSocket
}

// Wait for a server to start accepting connections at a unix domain socket.
func waitForServer(socket string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, socket, grpc.WithInsecure(), grpc.WithBlock(),
		grpc.WithDialer(func (socket string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", socket, timeout)
		}))

	if conn != nil {
		conn.Close()
	}

	return err
}

// Check if a server is accepting connections at the socket.
func serverActiveAt(socket string) bool {
	return waitForServer(socket, time.Second) == nil
}

// Wait for the removal of a file.
func watchFileRemoval(path string) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher for: %+v", err)
	}
	defer w.Close()

	if err := w.Add(filepath.Dir(path)); err != nil {
		return fmt.Errorf("failed to add '%s' to file watcher: %+v", path, err)
	}

	for {
		select {
			case evt := <-w.Events:
			if evt.Name == path {
				if evt.Op == fsnotify.Remove || evt.Op == fsnotify.Rename {
					return nil
				}
			}

			case err := <-w.Errors:
			return fmt.Errorf("file watcher error for %s: %+v", path, err)
		}
	}
}

