// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

func debugf(spec string, args ...interface{}) {
	if !opts.debug {
		return
	}
	fmt.Fprintf(os.Stderr, "DEBUG: "+spec, args...)
}

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

func (s *programStatus) Waffle(msg string) {
	if !opts.terse {
		s.Message(msg)
	}
}

func (s *programStatus) Wafflef(spec string, args ...interface{}) {
	if !opts.terse {
		s.Message(fmt.Sprintf(spec, args...))
	}
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

func (s *programStatus) ChildBatcher(label1, label2 string) (new *programStatus) {
	messages := make(chan string, 10)

	var label string
	if label2 != "" {
		label = fmt.Sprintf("%s[%s]", label1, label2)
	} else {
		label = label1
	}
	if s.label != "" {
		label = fmt.Sprintf("%s→%s", s.label, label)
	}

	new = &programStatus{
		probing:       s.probing,
		shuttingDown:  s.shuttingDown,
		batchChildren: &sync.WaitGroup{},
		output:        messages,
		label:         label,
	}

	s.probing.Add(1)       // shared
	s.batchChildren.Add(1) // unshared, deliberately the old one (parent)
	go batchedEmitMessages(messages, new, s)
	return new
}

func (s *programStatus) BatchFinished() {
	label := s.label
	if label == "" {
		label = "main(smtpdane)"
	}
	// wait for any of _our_ children to finish using us
	debugf("%s: we're finished\n", label)
	s.batchChildren.Wait()
	debugf("%s: and our children are done too\n", label)
	// then close ours
	close(s.output)

	s.probing.Done()
}

func batchedEmitMessages(src <-chan string, this, sink *programStatus) {
	batch := make([]string, 0, 50)
	for {
		msg, ok := <-src
		if !ok {
			break
		}
		if opts.debugFast {
			sink.Message(msg)
		} else {
			batch = append(batch, msg)
		}
	}
	// closed, so BatchFinished, so we _and_ our children are finished.

	errored := atomic.LoadUint32(&this.errorCount) != 0
	if errored {
		// race-safety: children exited, so nothing modifying our our
		// errorCount any more, could safely just reference it directly, so
		// there's no race between errored check above and this load here.
		//
		// We could just use .AddErr() but we want an accurate count preserved.
		_ = atomic.AddUint32(&sink.errorCount, atomic.LoadUint32(&this.errorCount))
	}
	if errored || !opts.quiet {
		for i := range batch {
			sink.Message(batch[i])
		}
	}

	// let parent know that we're done as a child user of its messaging channel, letting
	// it close output when ready to propagate.
	//
	// has had BatchFinished called, then the parent can close too.
	sink.batchChildren.Done()
	// top-level "things are in flight"
	sink.probing.Done()
}
