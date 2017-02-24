// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package errorlist

import (
	"fmt"
	"strings"
)

// List is our basic error-container representation.
type List []error

// if we switch to a struct, then include a "panicOnErrorIfEmpty" bool flag, so
// that calling error can panic, to expose coding bugs.

// New creates a new error container
func New() *List {
	l := make(List, 0, 10)
	return &l
}

// Add adds an error to the container
func (l *List) Add(e error) {
	*l = append(*l, e)
}

// AddErrorf is a convenience wrapper for Add(fmt.Errorf(...))
func (l *List) AddErrorf(spec string, args ...interface{}) {
	l.Add(fmt.Errorf(spec, args...))
}

// Len reports how many errors are in a container
func (l *List) Len() int {
	if l == nil || *l == nil {
		return 0
	}
	return len(*l)
}

// HasErrors is a predicate for the error-container being an error.
// (We can't dynamically switch type to get type-safety on that aspect.)
func (l *List) HasErrors() bool { return l.Len() > 0 }

// FmtEach applies a format-string to each error in the List, then joins the
// result on the supplied join string.
// If there are no errors then the result is guaranteed to be the empty string.
// The format-string should supply one format expando, which is given
// one error at a time.
func (l *List) FmtEach(spec, join string) string {
	if l.Len() == 0 {
		return ""
	}
	f := make([]string, len(*l))
	for i := range *l {
		f[i] = fmt.Sprintf(spec, (*l)[i])
	}
	return strings.Join(f, join)
}

func (l *List) FmtIndented() string { return l.FmtEach("\t%v\n", "") }
func (l *List) FmtList() string     { return "[" + l.FmtEach("(%v)", ", ") + "]" }

// Error returns the error string for the container, letting it be an error
// type in and of itself.  We reserve the right to panic if called on an
// empty container, to better expose checks.
func (l *List) Error() string {
	switch l.Len() {
	case 0:
		// TODO: should I go ahead and change this to a unilateral panic, always?
		return ""
	case 1:
		return (*l)[0].Error()
	default:
		return l.FmtList()
	}
}

// Maybe returns either an error which is this object, or nil.
// Use this to wrap the return results of an error accumulation for returning
// an error-or-nil.
func (l *List) Maybe() error {
	if l.Len() == 0 {
		return nil
	}
	return l
}

var _ error = New()
