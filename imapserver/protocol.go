package imapserver

import (
	"fmt"
	"time"

	"github.com/mjl-/mox/store"
)

type numSet struct {
	searchResult bool // "$"
	ranges       []numRange
}

// containsSeq returns whether seq is in the numSet, given uids and (saved) searchResult.
// uids and searchResult must be sorted. searchResult can have uids that are no longer in uids.
func (ss numSet) containsSeq(seq msgseq, uids []store.UID, searchResult []store.UID) bool {
	if len(uids) == 0 {
		return false
	}
	if ss.searchResult {
		uid := uids[int(seq)-1]
		return uidSearch(searchResult, uid) > 0 && uidSearch(uids, uid) > 0
	}
	for _, r := range ss.ranges {
		first := r.first.number
		if r.first.star {
			first = 1
		}
		last := first
		if r.last != nil {
			last = r.last.number
			if r.last.star {
				last = uint32(len(uids))
			}
		}
		if last > uint32(len(uids)) {
			last = uint32(len(uids))
		}
		if uint32(seq) >= first && uint32(seq) <= last {
			return true
		}
	}
	return false
}

func (ss numSet) containsUID(uid store.UID, uids []store.UID, searchResult []store.UID) bool {
	if len(uids) == 0 {
		return false
	}
	if ss.searchResult {
		return uidSearch(searchResult, uid) > 0 && uidSearch(uids, uid) > 0
	}
	for _, r := range ss.ranges {
		first := store.UID(r.first.number)
		if r.first.star {
			first = uids[0]
		}
		last := first
		// Num in <num>:* can be larger than last, but it still matches the last...
		// Similar for *:<num>. ../rfc/9051:4814
		if r.last != nil {
			last = store.UID(r.last.number)
			if r.last.star {
				last = uids[len(uids)-1]
				if first > last {
					first = last
				}
			} else if r.first.star && last < first {
				last = first
			}
		}
		if uid < first || uid > last {
			continue
		}
		if uidSearch(uids, uid) > 0 {
			return true
		}
	}
	return false
}

// contains returns whether the numset contains the number.
// only allowed on basic, strictly increasing numsets.
func (ss numSet) contains(v uint32) bool {
	for _, r := range ss.ranges {
		if r.first.number == v || r.last != nil && v > r.first.number && v <= r.last.number {
			return true
		}
	}
	return false
}

func (ss numSet) empty() bool {
	return !ss.searchResult && len(ss.ranges) == 0
}

// Strings returns the numset in zero or more strings of maxSize bytes. If
// maxSize is <= 0, a single string is returned.
func (ss numSet) Strings(maxSize int) []string {
	if ss.searchResult {
		return []string{"$"}
	}
	var l []string
	var line string
	for _, r := range ss.ranges {
		s := ""
		if r.first.star {
			s += "*"
		} else {
			s += fmt.Sprintf("%d", r.first.number)
		}
		if r.last == nil {
			if r.first.star {
				panic("invalid numSet range first star without last")
			}
		} else {
			s += ":"
			if r.last.star {
				s += "*"
			} else {
				s += fmt.Sprintf("%d", r.last.number)
			}
		}

		nsize := len(line) + len(s)
		if line != "" {
			nsize++ // comma
		}
		if maxSize > 0 && nsize > maxSize {
			l = append(l, line)
			line = s
			continue
		}
		if line != "" {
			line += ","
		}
		line += s
	}
	if line != "" {
		l = append(l, line)
	}
	return l
}

func (ss numSet) String() string {
	l := ss.Strings(0)
	if len(l) == 0 {
		return ""
	}
	return l[0]
}

type setNumber struct {
	number uint32
	star   bool
}

type numRange struct {
	first setNumber
	last  *setNumber // if nil, this numRange is just a setNumber in "first" and first.star will be false
}

// interpretStar returns a numset that interprets stars in a numset, returning a new
// numset without stars with increasing first/last.
func (s numSet) interpretStar(uids []store.UID) numSet {
	var ns numSet
	for _, r := range s.ranges {
		first := r.first.number
		if r.first.star {
			if len(uids) == 0 {
				continue
			}
			first = uint32(uids[0])
		}
		last := first
		if r.last != nil {
			last = r.last.number
			if r.last.star {
				if len(uids) == 0 {
					continue
				}
				last = uint32(uids[len(uids)-1])
				if first > last {
					first = last
				}
			} else if r.first.star && last < first {
				last = first
			}
		}
		if first > last {
			first, last = last, first
		}
		nr := numRange{first: setNumber{number: first}}
		if first != last {
			nr.last = &setNumber{number: last}
		}
		ns.ranges = append(ns.ranges, nr)
	}
	return ns
}

// whether numSet only has numbers (no star/search), and is strictly increasing.
func (s *numSet) isBasicIncreasing() bool {
	if s.searchResult {
		return false
	}
	var last uint32
	for _, r := range s.ranges {
		if r.first.star || r.first.number <= last || r.last != nil && (r.last.star || r.last.number < r.first.number) {
			return false
		}
		last = r.first.number
		if r.last != nil {
			last = r.last.number
		}
	}
	return true
}

type numIter struct {
	s numSet
	i int
	r *rangeIter
}

// newIter must only be called on a numSet that is basic (no star/search) and ascending.
func (s numSet) newIter() *numIter {
	return &numIter{s: s, i: 0, r: s.ranges[0].newIter()}
}

func (i *numIter) Next() (uint32, bool) {
	if v, ok := i.r.Next(); ok {
		return v, ok
	}
	i.i++
	if i.i >= len(i.s.ranges) {
		return 0, false
	}
	i.r = i.s.ranges[i.i].newIter()
	return i.r.Next()
}

type rangeIter struct {
	r numRange
	o int
}

// newIter must only be called on a range in a numSet that is basic (no star/search) and ascending.
func (r numRange) newIter() *rangeIter {
	return &rangeIter{r: r, o: 0}
}

func (r *rangeIter) Next() (uint32, bool) {
	if r.o == 0 {
		r.o++
		return r.r.first.number, true
	}
	if r.r.last == nil || r.r.first.number+uint32(r.o) > r.r.last.number {
		return 0, false
	}
	v := r.r.first.number + uint32(r.o)
	r.o++
	return v, true
}

// append adds a new number to the set, extending a range, or starting a new one (possibly the first).
// can only be used on basic numsets, without star/searchResult.
func (s *numSet) append(v uint32) {
	if len(s.ranges) == 0 {
		s.ranges = []numRange{{first: setNumber{number: v}}}
		return
	}
	ri := len(s.ranges) - 1
	r := s.ranges[ri]
	if v == r.first.number+1 && r.last == nil {
		s.ranges[ri].last = &setNumber{number: v}
	} else if r.last != nil && v == r.last.number+1 {
		r.last.number++
	} else {
		s.ranges = append(s.ranges, numRange{first: setNumber{number: v}})
	}
}

type partial struct {
	offset uint32
	count  uint32
}

type sectionPart struct {
	part []uint32
	text *sectionText
}

type sectionText struct {
	mime    bool // if "MIME"
	msgtext *sectionMsgtext
}

// a non-nil *sectionSpec with nil msgtext & nil part means there were []'s, but nothing inside. e.g. "BODY[]".
type sectionSpec struct {
	msgtext *sectionMsgtext
	part    *sectionPart
}

type sectionMsgtext struct {
	s       string   // "HEADER", "HEADER.FIELDS", "HEADER.FIELDS.NOT", "TEXT"
	headers []string // for "HEADER.FIELDS"*
}

type fetchAtt struct {
	field         string // uppercase, eg "ENVELOPE", "BODY". ".PEEK" is removed.
	peek          bool
	section       *sectionSpec
	sectionBinary []uint32
	partial       *partial
}

type searchKey struct {
	// Only one of searchKeys, seqSet and op can be non-nil/non-empty.
	searchKeys   []searchKey // In case of nested/multiple keys. Also for the top-level command.
	seqSet       *numSet     // In case of bare sequence set. For op UID, field uidSet contains the parameter.
	op           string      // Determines which of the fields below are set.
	headerField  string
	astring      string
	date         time.Time
	atom         string
	number       int64
	searchKey    *searchKey
	searchKey2   *searchKey
	uidSet       numSet
	clientModseq *int64
}

func compactUIDSet(l []store.UID) (r numSet) {
	for len(l) > 0 {
		e := 1
		for ; e < len(l) && l[e] == l[e-1]+1; e++ {
		}
		first := setNumber{number: uint32(l[0])}
		var last *setNumber
		if e > 1 {
			last = &setNumber{number: uint32(l[e-1])}
		}
		r.ranges = append(r.ranges, numRange{first, last})
		l = l[e:]
	}
	return
}
