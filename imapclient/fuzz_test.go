package imapclient

import (
	"os"
	"strings"
	"testing"
)

func FuzzParser(f *testing.F) {
	/*
		Gathering all untagged responses and command completion results from the RFCs:

		cd ../rfc
		(
		  grep ' S: \* [A-Z]' * | sed 's/^.*S: //g'
		  grep -E ' S: [^ *]+ (OK|NO|BAD) ' * | sed 's/^.*S: //g'
		) | grep -v '\.\.\/' | sort | uniq >../testdata/imapclient/fuzzseed.txt
	*/
	buf, err := os.ReadFile("../testdata/imapclient/fuzzseed.txt")
	if err != nil {
		f.Fatalf("reading seed: %v", err)
	}
	for _, s := range strings.Split(string(buf), "\n") {
		f.Add(s + "\r\n")
	}
	f.Add("1:3")
	f.Add("3:1")
	f.Add("3,1")
	f.Add("*")

	f.Fuzz(func(t *testing.T, data string) {
		ParseUntagged(data)
		ParseCode(data)
		ParseResult(data)
		ParseNumSet(data)
		ParseUIDRange(data)
	})
}
