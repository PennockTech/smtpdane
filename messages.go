// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// emitOutputMessages prints the messages it receives on the channel.
//
// We scan N hostnames, each of M IPs, in parallel.
// We emit messages and don't want them stomping on each other.  So we're
// a simple demultiplexer.
func emitOutputMessages(messages <-chan string, shuttingDown *sync.WaitGroup) {
	for {
		msg, ok := <-messages
		if !ok {
			break
		}
		fmt.Println(msg)
	}
	shuttingDown.Done()
}

func (s *programStatus) Messagef(spec string, args ...interface{}) {
	s.Message(fmt.Sprintf(spec, args...))
}

func (s *programStatus) Message(msg string) {
	s.output <- msg
}

func (s *programStatus) Error(msg string) {
	s.Message(ColorRed(msg))
	s.AddErr()
}

func (s *programStatus) Errorf(spec string, args ...interface{}) {
	s.Error(fmt.Sprintf(spec, args...))
}

func (s *programStatus) AddErr() {
	_ = atomic.AddUint32(&s.errorCount, 1)
}

func (s *programStatus) Successf(spec string, args ...interface{}) {
	s.Success(fmt.Sprintf(spec, args...))
}

func (s *programStatus) Success(msg string) {
	s.output <- ColorGreen(msg)
}
