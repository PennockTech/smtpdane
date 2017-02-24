// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package errorlist_test

import (
	"errors"
	"testing"

	"go.pennock.tech/smtpdane/internal/errorlist"

	"github.com/liquidgecka/testlib"
)

func TestBasics(t *testing.T) {
	T := testlib.NewT(t)
	defer T.Finish()

	el := errorlist.New()
	T.NotEqual(el, nil, "got nil return from errors.New")
	T.Equal(el.HasErrors(), false, "initial error-list has errors")
	T.Equal(el.Len(), 0, "initial error-list length is 0")
	T.Equal(el.FmtList(), "[]", "formatted as list, empty errors result non-empty list-repr")
	T.Equal(el.FmtIndented(), "", "formatted as lines, empty errors result non-empty")
	T.Equal(el.FmtEach("<%v>", "+"), "", "formatted each item, empty errors result non-empty")
	T.Equal(el.Error(), "", "error formatting is empty")
	T.ExpectSuccess(el.Maybe(), "not an error (yet)")

	e1 := errors.New("phil was here")
	e2 := errors.New("over here too")

	el.Add(e1)
	T.Equal(el.HasErrors(), true, "list of 1 error has error")
	T.Equal(el.Len(), 1, "list of 1 error length 1")
	T.Equal(el.FmtList(), "[(phil was here)]", "list-formatting of singleton list")
	T.Equal(el.FmtIndented(), "\tphil was here\n", "formatted as lines, singleton list")
	T.Equal(el.FmtEach("<%v>", "+"), "<phil was here>", "custom-formatting, singleton list")
	T.Equal(el.Error(), "phil was here", "basic error-repr of singleton is single error")
	T.ExpectError(el.Maybe(), "should have been an error")

	el.Add(e2)
	T.Equal(el.HasErrors(), true, "list of 2 error has error")
	T.Equal(el.Len(), 2, "list of 2 error length 2")
	T.Equal(el.FmtList(), "[(phil was here), (over here too)]", "list-formatting of list")
	T.Equal(el.FmtIndented(), "\tphil was here\n\tover here too\n", "formatted as lines, list")
	T.Equal(el.FmtEach("<%v>", "+"), "<phil was here>+<over here too>", "custom-formatting, list")
	T.Equal(el.Error(), "[(phil was here), (over here too)]", "basic error-repr of plural list is sequence of reprs")
	T.ExpectError(el.Maybe(), "should have been an error")

	el = errorlist.New()
	T.NotEqual(el, nil, "got nil return from errors.New")
	T.Equal(el.HasErrors(), false, "initial error-list has errors")
	el.AddErrorf("foo %v", 3)
	T.ExpectErrorMessage(el.Maybe(), "foo 3", "should have been an error \"foo 3\"")
	el = errorlist.New()
	el.AddErrorf("bar")
	T.ExpectErrorMessage(el.Maybe(), "bar", "should have been an error \"bar\"")
}
