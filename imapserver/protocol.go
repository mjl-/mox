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
				if last > first {
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

func (ss numSet) String() string {
	if ss.searchResult {
		return "$"
	}
	s := ""
	for _, r := range ss.ranges {
		if s != "" {
			s += ","
		}
		if r.first.star {
			s += "*"
		} else {
			s += fmt.Sprintf("%d", r.first.number)
		}
		if r.last == nil {
			if r.first.star {
				panic("invalid numSet range first star without last")
			}
			continue
		}
		s += ":"
		if r.last.star {
			s += "*"
		} else {
			s += fmt.Sprintf("%d", r.last.number)
		}
	}
	return s
}

type setNumber struct {
	number uint32
	star   bool
}

type numRange struct {
	first setNumber
	last  *setNumber // if nil, this numRange is just a setNumber in "first" and first.star will be false
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
	searchKeys  []searchKey // In case of nested/multiple keys. Also for the top-level command.
	seqSet      *numSet     // In case of bare sequence set. For op UID, field uidSet contains the parameter.
	op          string      // Determines which of the fields below are set.
	headerField string
	astring     string
	date        time.Time
	atom        string
	number      int64
	searchKey   *searchKey
	searchKey2  *searchKey
	uidSet      numSet
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
