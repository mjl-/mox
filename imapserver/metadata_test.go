package imapserver

import (
	"fmt"
	"testing"
	"time"

	"github.com/mjl-/mox/imapclient"
)

func TestMetadata(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", password0)

	tc.transactf("ok", `getmetadata "" /private/comment`)
	tc.xuntagged()

	tc.transactf("ok", `getmetadata inbox (/private/comment)`)
	tc.xuntagged()

	tc.transactf("ok", `setmetadata "" (/PRIVATE/COMMENT "global value")`)
	tc.transactf("ok", `setmetadata inbox (/private/comment "mailbox value")`)

	tc.transactf("ok", `getmetadata "" ("/private/comment")`)
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "",
		Annotations: []imapclient.Annotation{
			{Key: "/private/comment", IsString: true, Value: []byte("global value")},
		},
	})

	tc.transactf("ok", `getmetadata inbox (/private/comment /private/unknown /shared/comment)`)
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "Inbox",
		Annotations: []imapclient.Annotation{
			{Key: "/private/comment", IsString: true, Value: []byte("mailbox value")},
		},
	})

	tc.transactf("no", `setmetadata doesnotexist (/private/comment "test")`) // Bad mailbox.
	tc.transactf("no", `setmetadata Inbox (/shared/comment "")`)             // /shared/ not implemented.
	tc.transactf("no", `setmetadata Inbox (/badprefix/comment "")`)
	tc.transactf("no", `setmetadata Inbox (/private/vendor "")`)          // /*/vendor must have more components.
	tc.transactf("no", `setmetadata Inbox (/private/vendor/stillbad "")`) // /*/vendor must have more components.
	tc.transactf("ok", `setmetadata Inbox (/private/vendor/a/b "")`)
	tc.transactf("bad", `setmetadata Inbox (/private/no* "")`)
	tc.transactf("bad", `setmetadata Inbox (/private/no%% "")`)
	tc.transactf("bad", `setmetadata Inbox (/private/notrailingslash/ "")`)
	tc.transactf("bad", `setmetadata Inbox (/private//nodupslash "")`)
	tc.transactf("bad", "setmetadata Inbox (/private/\001 \"\")")
	tc.transactf("bad", "setmetadata Inbox (/private/\u007f \"\")")
	tc.transactf("bad", `getmetadata (depth 0 depth 0) inbox (/private/a)`) // Duplicate option.
	tc.transactf("bad", `getmetadata (depth badvalue) inbox (/private/a)`)
	tc.transactf("bad", `getmetadata (maxsize invalid) inbox (/private/a)`)
	tc.transactf("bad", `getmetadata (badoption) inbox (/private/a)`)

	// Update existing annotation by key.
	tc.transactf("ok", `setmetadata "" (/PRIVATE/COMMENT "global updated")`)
	tc.transactf("ok", `setmetadata inbox (/private/comment "mailbox updated")`)
	tc.transactf("ok", `getmetadata "" (/private/comment)`)
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "",
		Annotations: []imapclient.Annotation{
			{Key: "/private/comment", IsString: true, Value: []byte("global updated")},
		},
	})
	tc.transactf("ok", `getmetadata inbox (/private/comment)`)
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "Inbox",
		Annotations: []imapclient.Annotation{
			{Key: "/private/comment", IsString: true, Value: []byte("mailbox updated")},
		},
	})

	// Delete annotation with nil value.
	tc.transactf("ok", `setmetadata "" (/private/comment nil)`)
	tc.transactf("ok", `setmetadata inbox (/private/comment nil)`)
	tc.transactf("ok", `getmetadata "" (/private/comment)`)
	tc.xuntagged()
	tc.transactf("ok", `getmetadata inbox (/private/comment)`)
	tc.xuntagged()

	// Create a literal8 value, not a string.
	tc.transactf("ok", "setmetadata inbox (/private/comment ~{4+}\r\ntest)")
	tc.transactf("ok", `getmetadata inbox (/private/comment)`)
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "Inbox",
		Annotations: []imapclient.Annotation{
			{Key: "/private/comment", IsString: false, Value: []byte("test")},
		},
	})

	// Request with a maximum size, we don't get anything larger.
	tc.transactf("ok", `setmetadata inbox (/private/another "longer")`)
	tc.transactf("ok", `getmetadata (maxsize 4) inbox (/private/comment /private/another)`)
	tc.xcodeArg(imapclient.CodeOther{Code: "METADATA", Args: []string{"LONGENTRIES", "6"}})
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "Inbox",
		Annotations: []imapclient.Annotation{
			{Key: "/private/comment", IsString: false, Value: []byte("test")},
		},
	})

	// Request with various depth values.
	tc.transactf("ok", `setmetadata inbox (/private/a "x" /private/a/b "x" /private/a/b/c "x" /private/a/b/c/d "x")`)
	tc.transactf("ok", `getmetadata (depth 0) inbox (/private/a)`)
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "Inbox",
		Annotations: []imapclient.Annotation{
			{Key: "/private/a", IsString: true, Value: []byte("x")},
		},
	})
	tc.transactf("ok", `getmetadata (depth 1) inbox (/private/a)`)
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "Inbox",
		Annotations: []imapclient.Annotation{
			{Key: "/private/a", IsString: true, Value: []byte("x")},
			{Key: "/private/a/b", IsString: true, Value: []byte("x")},
		},
	})
	tc.transactf("ok", `getmetadata (depth infinity) inbox (/private/a)`)
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "Inbox",
		Annotations: []imapclient.Annotation{
			{Key: "/private/a", IsString: true, Value: []byte("x")},
			{Key: "/private/a/b", IsString: true, Value: []byte("x")},
			{Key: "/private/a/b/c", IsString: true, Value: []byte("x")},
			{Key: "/private/a/b/c/d", IsString: true, Value: []byte("x")},
		},
	})
	// Same as previous, but ask for everything below /.
	tc.transactf("ok", `getmetadata (depth infinity) inbox (/)`)
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "Inbox",
		Annotations: []imapclient.Annotation{
			{Key: "/private/a", IsString: true, Value: []byte("x")},
			{Key: "/private/a/b", IsString: true, Value: []byte("x")},
			{Key: "/private/a/b/c", IsString: true, Value: []byte("x")},
			{Key: "/private/a/b/c/d", IsString: true, Value: []byte("x")},
			{Key: "/private/another", IsString: true, Value: []byte("longer")},
			{Key: "/private/comment", IsString: false, Value: []byte("test")},
			{Key: "/private/vendor/a/b", IsString: true, Value: []byte("")},
		},
	})

	// Deleting a mailbox with an annotation should work and annotations should not
	// come back when recreating mailbox.
	tc.transactf("ok", "create testbox")
	tc.transactf("ok", `setmetadata testbox (/private/a "x")`)
	tc.transactf("ok", "delete testbox")
	tc.transactf("ok", "create testbox")
	tc.transactf("ok", `getmetadata testbox (/private/a)`)
	tc.xuntagged()

	// When renaming mailbox, annotations must be copied to destination mailbox.
	tc.transactf("ok", "rename inbox newbox")
	tc.transactf("ok", `getmetadata newbox (/private/a)`)
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "newbox",
		Annotations: []imapclient.Annotation{
			{Key: "/private/a", IsString: true, Value: []byte("x")},
		},
	})
	tc.transactf("ok", `getmetadata inbox (/private/a)`)
	tc.xuntagged(imapclient.UntaggedMetadataAnnotations{
		Mailbox: "Inbox",
		Annotations: []imapclient.Annotation{
			{Key: "/private/a", IsString: true, Value: []byte("x")},
		},
	})

	// Broadcast should not happen when metadata capability is not enabled.
	tc2 := startNoSwitchboard(t)
	defer tc2.close()
	tc2.client.Login("mjl@mox.example", password0)
	tc2.client.Select("inbox")

	tc2.cmdf("", "idle")
	tc2.readprefixline("+ ")
	done := make(chan error)
	go func() {
		defer func() {
			x := recover()
			if x != nil {
				done <- fmt.Errorf("%v", x)
			}
		}()
		untagged, _ := tc2.client.ReadUntagged()
		var exists imapclient.UntaggedExists
		tuntagged(tc2.t, untagged, &exists)
		tc2.writelinef("done")
		tc2.response("ok")
		done <- nil
	}()

	// Should not cause idle to return.
	tc.transactf("ok", `setmetadata inbox (/private/a "y")`)
	// Cause to return.
	tc.transactf("ok", "append inbox {4+}\r\ntest")

	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		tc.check(err, "idle")
	case <-timer.C:
		t.Fatalf("idle did not finish")
	}

	// Broadcast should happen when metadata capability is enabled.
	tc2.client.Enable(string(imapclient.CapMetadata))
	tc2.cmdf("", "idle")
	tc2.readprefixline("+ ")
	done = make(chan error)
	go func() {
		defer func() {
			x := recover()
			if x != nil {
				done <- fmt.Errorf("%v", x)
			}
		}()
		untagged, _ := tc2.client.ReadUntagged()
		var metadataKeys imapclient.UntaggedMetadataKeys
		tuntagged(tc2.t, untagged, &metadataKeys)
		tc2.writelinef("done")
		tc2.response("ok")
		done <- nil
	}()

	// Should cause idle to return.
	tc.transactf("ok", `setmetadata inbox (/private/a "z")`)

	timer = time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		tc.check(err, "idle")
	case <-timer.C:
		t.Fatalf("idle did not finish")
	}
}

func TestMetadataLimit(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", password0)

	maxKeys, maxSize := metadataMaxKeys, metadataMaxSize
	defer func() {
		metadataMaxKeys = maxKeys
		metadataMaxSize = maxSize
	}()
	metadataMaxKeys = 10
	metadataMaxSize = 1000

	// Reach max total size limit.
	buf := make([]byte, metadataMaxSize+1)
	for i := range buf {
		buf[i] = 'x'
	}
	tc.cmdf("", "setmetadata inbox (/private/large ~{%d+}", len(buf))
	tc.client.Write(buf)
	tc.client.Writelinef(")")
	tc.response("no")
	tc.xcodeArg(imapclient.CodeOther{Code: "METADATA", Args: []string{"MAXSIZE", fmt.Sprintf("%d", metadataMaxSize)}})

	// Reach limit for max number.
	for i := 1; i <= metadataMaxKeys; i++ {
		tc.transactf("ok", `setmetadata inbox (/private/key%d "test")`, i)
	}
	tc.transactf("no", `setmetadata inbox (/private/toomany "test")`)
	tc.xcodeArg(imapclient.CodeOther{Code: "METADATA", Args: []string{"TOOMANY"}})
}
