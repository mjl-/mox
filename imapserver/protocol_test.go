package imapserver

import (
	"testing"

	"github.com/mjl-/mox/store"
)

func TestNumSetContains(t *testing.T) {
	num := func(v uint32) *setNumber {
		return &setNumber{v, false}
	}
	star := &setNumber{star: true}

	check := func(v bool) {
		t.Helper()
		if !v {
			t.Fatalf("bad")
		}
	}

	ss0 := numSet{true, nil} // "$"
	check(ss0.containsSeq(1, []store.UID{2}, []store.UID{2}))
	check(!ss0.containsSeq(1, []store.UID{2}, []store.UID{}))

	check(ss0.containsUID(1, []store.UID{1}, []store.UID{1}))
	check(ss0.containsUID(2, []store.UID{1, 2, 3}, []store.UID{2}))
	check(!ss0.containsUID(2, []store.UID{1, 2, 3}, []store.UID{}))
	check(!ss0.containsUID(2, []store.UID{}, []store.UID{2}))

	ss1 := numSet{false, []numRange{{*num(1), nil}}} // Single number 1.
	check(ss1.containsSeq(1, []store.UID{2}, nil))
	check(!ss1.containsSeq(2, []store.UID{1, 2}, nil))

	check(ss1.containsUID(1, []store.UID{1}, nil))
	check(ss1.containsSeq(1, []store.UID{2}, nil))
	check(!ss1.containsSeq(2, []store.UID{1, 2}, nil))

	// 2:*
	ss2 := numSet{false, []numRange{{*num(2), star}}}
	check(!ss2.containsSeq(1, []store.UID{2}, nil))
	check(ss2.containsSeq(2, []store.UID{4, 5}, nil))
	check(ss2.containsSeq(3, []store.UID{4, 5, 6}, nil))

	check(ss2.containsUID(2, []store.UID{2}, nil))
	check(ss2.containsUID(3, []store.UID{1, 2, 3}, nil))
	check(ss2.containsUID(2, []store.UID{2}, nil))
	check(!ss2.containsUID(2, []store.UID{4, 5}, nil))
	check(!ss2.containsUID(2, []store.UID{1}, nil))

	check(ss2.containsUID(2, []store.UID{2, 6}, nil))
	check(ss2.containsUID(6, []store.UID{2, 6}, nil))

	// *:2
	ss3 := numSet{false, []numRange{{*star, num(2)}}}
	check(ss3.containsSeq(1, []store.UID{2}, nil))
	check(ss3.containsSeq(2, []store.UID{4, 5}, nil))
	check(!ss3.containsSeq(3, []store.UID{1, 2, 3}, nil))

	check(ss3.containsUID(1, []store.UID{1}, nil))
	check(ss3.containsUID(2, []store.UID{1, 2, 3}, nil))
	check(!ss3.containsUID(1, []store.UID{2, 3}, nil))
	check(!ss3.containsUID(3, []store.UID{1, 2, 3}, nil))
}

func TestNumSetInterpret(t *testing.T) {
	parseNumSet := func(s string) numSet {
		p := parser{upper: s}
		return p.xnumSet0(true, false)
	}

	checkEqual := func(uids []store.UID, a, s string) {
		t.Helper()
		n := parseNumSet(a).interpretStar(uids)
		ns := n.String()
		if ns != s {
			t.Fatalf("%s != %s", ns, s)
		}
	}

	checkEqual([]store.UID{}, "1:*", "")
	checkEqual([]store.UID{1}, "1:*", "1")
	checkEqual([]store.UID{1, 3}, "1:*", "1:3")
	checkEqual([]store.UID{1, 3}, "4:*", "3")
	checkEqual([]store.UID{2, 3}, "*:4", "2:4")
	checkEqual([]store.UID{2, 3}, "*:1", "2")
	checkEqual([]store.UID{1, 2, 3}, "1,2,3", "1,2,3")
	checkEqual([]store.UID{}, "1,2,3", "1,2,3")
	checkEqual([]store.UID{}, "1:3", "1:3")
	checkEqual([]store.UID{}, "3:1", "1:3")
}
