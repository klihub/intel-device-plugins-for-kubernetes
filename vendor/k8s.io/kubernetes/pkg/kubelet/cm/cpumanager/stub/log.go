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
	"github.com/golang/glog"
)

type logger struct {
	prefix string
}

type Logger interface {
	Format(format string, args ...interface{}) string
	Message(level glog.Level, format string, args ...interface{})
	Info(format string, args ...interface{})
	Warning(format string, args ...interface{})
	Error(format string, args ...interface{})
	Fatal(format string, args ...interface{})
	Panic(format string, args ...interface{})
}

var _ Logger = &logger{}

func NewLogger(prefix string) Logger {
	return &logger{ prefix: prefix }
}

func (log *logger) Format(format string, args ...interface{}) string {
	return fmt.Sprintf(log.prefix + format, args...)
}

func (log *logger) Message(level glog.Level, format string, args ...interface{}) {
	if !glog.V(level) {
		glog.InfoDepth(1, log.Format(format, args...))
	}
}

func (log *logger) Info(format string, args ...interface{}) {
	glog.InfoDepth(1, log.Format(format, args...))
}

func (log *logger) Warning(format string, args ...interface{}) {
	glog.WarningDepth(1, log.Format(format, args...))
}

func (log *logger) Error(format string, args ...interface{}) {
	glog.ErrorDepth(1, log.Format(format, args...))
}

func (log *logger) Fatal(format string, args ...interface{}) {
	glog.FatalDepth(1, log.Format(format, args...))
}

func (log *logger) Panic(format string, args ...interface{}) {
	msg := log.Format(format, args...)
	panic(msg)
}
