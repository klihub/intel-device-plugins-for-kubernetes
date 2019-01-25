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
	"fmt"
	"k8s.io/klog"
)

type logger struct {
	prefix  string
}

type Logger interface {
	Format(format string, args ...interface{}) string
	Info(format string, args ...interface{})
	Warning(format string, args ...interface{})
	Error(format string, args ...interface{})
	Fatal(format string, args ...interface{})
	Panic(format string, args ...interface{})
}

type Backend interface {
	Infof(string, ...interface{})
	InfoDepth(int, ...interface{})
	WarningDepth(int, ...interface{})
	ErrorDepth(int, ...interface{})
	FatalDepth(int, ...interface{})
}

type klogBackend struct {}

var _ Backend = &klogBackend{}
var _ Logger = &logger{}

var backend Backend = &klogBackend{}

func NewLogger(prefix string) Logger {
	return &logger{ prefix: prefix }
}

func SetBackend(be Backend) {
	backend = be
}

func (log *logger) Format(format string, args ...interface{}) string {
	return fmt.Sprintf(log.prefix + format, args...)
}

func (log *logger) Info(format string, args ...interface{}) {
	backend.Infof(log.Format(format, args...))
}

func (log *logger) Warning(format string, args ...interface{}) {
	backend.WarningDepth(2, log.Format(format, args...))
}

func (log *logger) Error(format string, args ...interface{}) {
	backend.ErrorDepth(2, log.Format(format, args...))
}

func (log *logger) Fatal(format string, args ...interface{}) {
	backend.FatalDepth(2, log.Format(format, args...))
}

func (log *logger) Panic(format string, args ...interface{}) {
	msg := log.Format(format, args...)
	panic(msg)
}


func (klb *klogBackend) Infof(format string, args ...interface{}) {
	klog.InfoDepth(2, log.Format(format, args...))
}

func (klb *klogBackend) InfoDepth(level int, args ...interface{}) {
	klog.InfoDepth(level, args...)
}

func (klb *klogBackend) WarningDepth(level int, args ...interface{}) {
	klog.WarningDepth(level, args...)
}

func (klb *klogBackend) ErrorDepth(level int, args ...interface{}) {
	klog.ErrorDepth(level, args...)
}

func (klb *klogBackend) FatalDepth(level int, args ...interface{}) {
	klog.FatalDepth(level, args...)
}

