package imapserver

import (
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/imapclient"
)

func TestFetch(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", password0)
	tc.client.Enable("imap4rev2")
	received, err := time.Parse(time.RFC3339, "2022-11-16T10:01:00+01:00")
	tc.check(err, "parse time")
	tc.client.Append("inbox", nil, &received, []byte(exampleMsg))
	tc.client.Select("inbox")

	uid1 := imapclient.FetchUID(1)
	date1 := imapclient.FetchInternalDate("16-Nov-2022 10:01:00 +0100")
	rfcsize1 := imapclient.FetchRFC822Size(len(exampleMsg))
	env1 := imapclient.FetchEnvelope{
		Date:      "Mon, 7 Feb 1994 21:52:25 -0800",
		Subject:   "afternoon meeting",
		From:      []imapclient.Address{{Name: "Fred Foobar", Mailbox: "foobar", Host: "blurdybloop.example"}},
		Sender:    []imapclient.Address{{Name: "Fred Foobar", Mailbox: "foobar", Host: "blurdybloop.example"}},
		ReplyTo:   []imapclient.Address{{Name: "Fred Foobar", Mailbox: "foobar", Host: "blurdybloop.example"}},
		To:        []imapclient.Address{{Mailbox: "mooch", Host: "owatagu.siam.edu.example"}},
		MessageID: "<B27397-0100000@Blurdybloop.example>",
	}
	noflags := imapclient.FetchFlags(nil)
	bodyxstructure1 := imapclient.FetchBodystructure{
		RespAttr: "BODY",
		Body: imapclient.BodyTypeText{
			MediaType:    "TEXT",
			MediaSubtype: "PLAIN",
			BodyFields: imapclient.BodyFields{
				Params: [][2]string{[...]string{"CHARSET", "US-ASCII"}},
				Octets: 57,
			},
			Lines: 2,
		},
	}
	bodystructure1 := bodyxstructure1
	bodystructure1.RespAttr = "BODYSTRUCTURE"

	split := strings.SplitN(exampleMsg, "\r\n\r\n", 2)
	exampleMsgHeader := split[0] + "\r\n\r\n"
	exampleMsgBody := split[1]

	binary1 := imapclient.FetchBinary{RespAttr: "BINARY[]", Data: exampleMsg}
	binarypart1 := imapclient.FetchBinary{RespAttr: "BINARY[1]", Parts: []uint32{1}, Data: exampleMsgBody}
	binarypartial1 := imapclient.FetchBinary{RespAttr: "BINARY[]", Data: exampleMsg[1:2]}
	binarypartpartial1 := imapclient.FetchBinary{RespAttr: "BINARY[1]", Parts: []uint32{1}, Data: exampleMsgBody[1:2]}
	binaryend1 := imapclient.FetchBinary{RespAttr: "BINARY[]", Data: ""}
	binarypartend1 := imapclient.FetchBinary{RespAttr: "BINARY[1]", Parts: []uint32{1}, Data: ""}
	binarysize1 := imapclient.FetchBinarySize{RespAttr: "BINARY.SIZE[]", Size: int64(len(exampleMsg))}
	binarysizepart1 := imapclient.FetchBinarySize{RespAttr: "BINARY.SIZE[1]", Parts: []uint32{1}, Size: int64(len(exampleMsgBody))}
	bodyheader1 := imapclient.FetchBody{RespAttr: "BODY[HEADER]", Section: "HEADER", Body: exampleMsgHeader}
	bodytext1 := imapclient.FetchBody{RespAttr: "BODY[TEXT]", Section: "TEXT", Body: exampleMsgBody}
	body1 := imapclient.FetchBody{RespAttr: "BODY[]", Body: exampleMsg}
	bodypart1 := imapclient.FetchBody{RespAttr: "BODY[1]", Section: "1", Body: exampleMsgBody}
	bodyoff1 := imapclient.FetchBody{RespAttr: "BODY[]<1>", Section: "", Offset: 1, Body: exampleMsg[1:3]}
	body1off1 := imapclient.FetchBody{RespAttr: "BODY[1]<1>", Section: "1", Offset: 1, Body: exampleMsgBody[1:3]}
	bodyend1 := imapclient.FetchBody{RespAttr: "BODY[1]<100000>", Section: "1", Offset: 100000, Body: ""} // todo: should offset be what was requested, or the size of the message?
	rfcheader1 := imapclient.FetchRFC822Header(exampleMsgHeader)
	rfctext1 := imapclient.FetchRFC822Text(exampleMsgBody)
	rfc1 := imapclient.FetchRFC822(exampleMsg)
	headerSplit := strings.SplitN(exampleMsgHeader, "\r\n", 2)
	dateheader1 := imapclient.FetchBody{RespAttr: "BODY[HEADER.FIELDS (Date)]", Section: "HEADER.FIELDS (Date)", Body: headerSplit[0] + "\r\n\r\n"}
	nodateheader1 := imapclient.FetchBody{RespAttr: "BODY[HEADER.FIELDS.NOT (Date)]", Section: "HEADER.FIELDS.NOT (Date)", Body: headerSplit[1]}
	date1header1 := imapclient.FetchBody{RespAttr: "BODY[1.HEADER.FIELDS (Date)]", Section: "1.HEADER.FIELDS (Date)", Body: headerSplit[0] + "\r\n\r\n"}
	nodate1header1 := imapclient.FetchBody{RespAttr: "BODY[1.HEADER.FIELDS.NOT (Date)]", Section: "1.HEADER.FIELDS.NOT (Date)", Body: headerSplit[1]}
	mime1 := imapclient.FetchBody{RespAttr: "BODY[1.MIME]", Section: "1.MIME", Body: "MIME-Version: 1.0\r\nContent-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n\r\n"}

	flagsSeen := imapclient.FetchFlags{`\Seen`}

	tc.transactf("ok", "fetch 1 all")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, date1, rfcsize1, env1, noflags}})

	tc.transactf("ok", "fetch 1 fast")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, date1, rfcsize1, noflags}})

	tc.transactf("ok", "fetch 1 full")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, date1, rfcsize1, env1, bodyxstructure1, noflags}})

	tc.transactf("ok", "fetch 1 flags")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, noflags}})

	tc.transactf("ok", "fetch 1 bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodystructure1}})

	// Should be returned unmodified, because there is no content-transfer-encoding.
	tc.transactf("ok", "fetch 1 binary[]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, binary1, flagsSeen}})

	tc.transactf("ok", "fetch 1 binary[1]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, binarypart1}}) // Seen flag not changed.

	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 binary[]<1.1>")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, binarypartial1, flagsSeen}})

	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 binary[1]<1.1>")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, binarypartpartial1, flagsSeen}})

	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 binary[]<10000.10001>")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, binaryend1, flagsSeen}})

	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 binary[1]<10000.10001>")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, binarypartend1, flagsSeen}})

	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 binary.size[]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, binarysize1}})

	tc.transactf("ok", "fetch 1 binary.size[1]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, binarysizepart1}})

	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 body[]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, body1, flagsSeen}})
	tc.transactf("ok", "fetch 1 body[]<1.2>")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodyoff1}}) // Already seen.

	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 body[1]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodypart1, flagsSeen}})

	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 body[1]<1.2>")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, body1off1, flagsSeen}})

	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 body[1]<100000.100000>")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodyend1, flagsSeen}})

	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 body[header]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodyheader1, flagsSeen}})

	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 body[text]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodytext1, flagsSeen}})

	// equivalent to body.peek[header], ../rfc/3501:3183
	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 rfc822.header")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, rfcheader1}})

	// equivalent to body[text], ../rfc/3501:3199
	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 rfc822.text")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, rfctext1, flagsSeen}})

	// equivalent to body[], ../rfc/3501:3179
	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 rfc822")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, rfc1, flagsSeen}})

	// With PEEK, we should not get the \Seen flag.
	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.transactf("ok", "fetch 1 body.peek[]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, body1}})

	tc.transactf("ok", "fetch 1 binary.peek[]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, binary1}})

	// HEADER.FIELDS and .NOT
	tc.transactf("ok", "fetch 1 body.peek[header.fields (date)]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, dateheader1}})
	tc.transactf("ok", "fetch 1 body.peek[header.fields.not (date)]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, nodateheader1}})
	// For non-multipart messages, 1 means the whole message. ../rfc/9051:4481
	tc.transactf("ok", "fetch 1 body.peek[1.header.fields (date)]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, date1header1}})
	tc.transactf("ok", "fetch 1 body.peek[1.header.fields.not (date)]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, nodate1header1}})

	// MIME, part 1 for non-multipart messages is the message itself. ../rfc/9051:4481
	tc.transactf("ok", "fetch 1 body.peek[1.mime]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, mime1}})

	// Missing sequence number. ../rfc/9051:7018
	tc.transactf("bad", "fetch 2 body[]")

	tc.transactf("ok", "fetch 1:1 body[]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, body1, flagsSeen}})

	// UID fetch
	tc.transactf("ok", "uid fetch 1 body[]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, body1}})

	// UID fetch
	tc.transactf("ok", "uid fetch 2 body[]")
	tc.xuntagged()

	// Test some invalid syntax.
	tc.transactf("bad", "fetch")
	tc.transactf("bad", "fetch ")
	tc.transactf("bad", "fetch  ")
	tc.transactf("bad", "fetch 1")    // At least one requested item required.
	tc.transactf("bad", "fetch 1 ()") // Empty list not allowed
	tc.transactf("bad", "fetch 1 unknown")
	tc.transactf("bad", "fetch 1 (unknown)")
	tc.transactf("bad", "fetch 1 (all)")                      // Macro's not allowed in list.
	tc.transactf("bad", "fetch 1 binary")                     // [] required
	tc.transactf("bad", "fetch 1 binary[text]")               // Text/header etc only allowed for body[].
	tc.transactf("bad", "fetch 1 binary[]<1>")                // Count required.
	tc.transactf("bad", "fetch 1 binary[]<1.0>")              // Count must be > 0.
	tc.transactf("bad", "fetch 1 binary[]<1..1>")             // Single dot.
	tc.transactf("bad", "fetch 1 body[]<1>")                  // Count required.
	tc.transactf("bad", "fetch 1 body[]<1.0>")                // Count must be > 0.
	tc.transactf("bad", "fetch 1 body[]<1..1>")               // Single dot.
	tc.transactf("bad", "fetch 1 body[header.fields]")        // List of headers required.
	tc.transactf("bad", "fetch 1 body[header.fields ()]")     // List must be non-empty.
	tc.transactf("bad", "fetch 1 body[header.fields.not]")    // List of headers required.
	tc.transactf("bad", "fetch 1 body[header.fields.not ()]") // List must be non-empty.
	tc.transactf("bad", "fetch 1 body[mime]")                 // MIME must be prefixed with a number. ../rfc/9051:4497

	tc.transactf("no", "fetch 1 body[2]") // No such part.

	// Add more complex message.

	uid2 := imapclient.FetchUID(2)
	bodystructure2 := imapclient.FetchBodystructure{
		RespAttr: "BODYSTRUCTURE",
		Body: imapclient.BodyTypeMpart{
			Bodies: []any{
				imapclient.BodyTypeBasic{BodyFields: imapclient.BodyFields{Octets: 275}},
				imapclient.BodyTypeText{MediaType: "TEXT", MediaSubtype: "PLAIN", BodyFields: imapclient.BodyFields{Params: [][2]string{{"CHARSET", "US-ASCII"}}, Octets: 114}, Lines: 3},
				imapclient.BodyTypeMpart{
					Bodies: []any{
						imapclient.BodyTypeBasic{MediaType: "AUDIO", MediaSubtype: "BASIC", BodyFields: imapclient.BodyFields{CTE: "BASE64", Octets: 22}},
						imapclient.BodyTypeBasic{MediaType: "IMAGE", MediaSubtype: "JPEG", BodyFields: imapclient.BodyFields{CTE: "BASE64"}},
					},
					MediaSubtype: "PARALLEL",
				},
				imapclient.BodyTypeText{MediaType: "TEXT", MediaSubtype: "ENRICHED", BodyFields: imapclient.BodyFields{Octets: 145}, Lines: 5},
				imapclient.BodyTypeMsg{
					MediaType:    "MESSAGE",
					MediaSubtype: "RFC822",
					BodyFields:   imapclient.BodyFields{Octets: 228},
					Envelope: imapclient.Envelope{
						Subject: "(subject in US-ASCII)",
						From:    []imapclient.Address{{Name: "", Adl: "", Mailbox: "info", Host: "mox.example"}},
						Sender:  []imapclient.Address{{Name: "", Adl: "", Mailbox: "info", Host: "mox.example"}},
						ReplyTo: []imapclient.Address{{Name: "", Adl: "", Mailbox: "info", Host: "mox.example"}},
						To:      []imapclient.Address{{Name: "mox", Adl: "", Mailbox: "info", Host: "mox.example"}},
					},
					Bodystructure: imapclient.BodyTypeText{
						MediaType: "TEXT", MediaSubtype: "PLAIN", BodyFields: imapclient.BodyFields{Params: [][2]string{{"CHARSET", "ISO-8859-1"}}, CTE: "QUOTED-PRINTABLE", Octets: 51}, Lines: 1},
					Lines: 7,
				},
			},
			MediaSubtype: "MIXED",
		},
	}
	tc.client.Append("inbox", nil, &received, []byte(nestedMessage))
	tc.transactf("ok", "fetch 2 bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})

	// Multiple responses.
	tc.transactf("ok", "fetch 1:2 bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodystructure1}}, imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})
	tc.transactf("ok", "fetch 1,2 bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodystructure1}}, imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})
	tc.transactf("ok", "fetch 2:1 bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodystructure1}}, imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})
	tc.transactf("ok", "fetch 1:* bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodystructure1}}, imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})
	tc.transactf("ok", "fetch *:1 bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodystructure1}}, imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})
	tc.transactf("ok", "fetch *:2 bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})

	tc.transactf("ok", "fetch * bodystructure") // Highest msgseq.
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})

	tc.transactf("ok", "uid fetch 1:* bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodystructure1}}, imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})

	tc.transactf("ok", "uid fetch 1:2 bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodystructure1}}, imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})

	tc.transactf("ok", "uid fetch 1,2 bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, bodystructure1}}, imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})

	tc.transactf("ok", "uid fetch 2:2 bodystructure")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, bodystructure2}})

	// todo: read the bodies/headers of the parts, and of the nested message.
	tc.transactf("ok", "fetch 2 body.peek[]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBody{RespAttr: "BODY[]", Body: nestedMessage}}})

	part1 := tocrlf(`  ... Some text appears here ...

[Note that the blank between the boundary and the start
 of the text in this part means no header fields were
 given and this is text in the US-ASCII character set.
 It could have been done with explicit typing as in the
 next part.]
`)
	tc.transactf("ok", "fetch 2 body.peek[1]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBody{RespAttr: "BODY[1]", Section: "1", Body: part1}}})

	tc.transactf("no", "fetch 2 binary.peek[3]") // Only allowed on leaf parts, not multiparts.
	tc.transactf("no", "fetch 2 binary.peek[5]") // Only allowed on leaf parts, not messages.

	part31 := "aGVsbG8NCndvcmxkDQo=\r\n"
	part31dec := "hello\r\nworld\r\n"
	tc.transactf("ok", "fetch 2 binary.size[3.1]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBinarySize{RespAttr: "BINARY.SIZE[3.1]", Parts: []uint32{3, 1}, Size: int64(len(part31dec))}}})

	tc.transactf("ok", "fetch 2 body.peek[3.1]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBody{RespAttr: "BODY[3.1]", Section: "3.1", Body: part31}}})

	tc.transactf("ok", "fetch 2 binary.peek[3.1]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBinary{RespAttr: "BINARY[3.1]", Parts: []uint32{3, 1}, Data: part31dec}}})

	part3 := tocrlf(`--unique-boundary-2
Content-Type: audio/basic
Content-Transfer-Encoding: base64

aGVsbG8NCndvcmxkDQo=

--unique-boundary-2
Content-Type: image/jpeg
Content-Transfer-Encoding: base64


--unique-boundary-2--

`)
	tc.transactf("ok", "fetch 2 body.peek[3]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBody{RespAttr: "BODY[3]", Section: "3", Body: part3}}})

	part2mime := tocrlf(`Content-type: text/plain; charset=US-ASCII

`)
	tc.transactf("ok", "fetch 2 body.peek[2.mime]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBody{RespAttr: "BODY[2.MIME]", Section: "2.MIME", Body: part2mime}}})

	part5 := tocrlf(`From: info@mox.example
To: mox <info@mox.example>
Subject: (subject in US-ASCII)
Content-Type: Text/plain; charset=ISO-8859-1
Content-Transfer-Encoding: Quoted-printable

  ... Additional text in ISO-8859-1 goes here ...
`)
	tc.transactf("ok", "fetch 2 body.peek[5]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBody{RespAttr: "BODY[5]", Section: "5", Body: part5}}})

	part5header := tocrlf(`From: info@mox.example
To: mox <info@mox.example>
Subject: (subject in US-ASCII)
Content-Type: Text/plain; charset=ISO-8859-1
Content-Transfer-Encoding: Quoted-printable

`)
	tc.transactf("ok", "fetch 2 body.peek[5.header]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBody{RespAttr: "BODY[5.HEADER]", Section: "5.HEADER", Body: part5header}}})

	part5mime := tocrlf(`Content-Type: Text/plain; charset=ISO-8859-1
Content-Transfer-Encoding: Quoted-printable

`)
	tc.transactf("ok", "fetch 2 body.peek[5.mime]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBody{RespAttr: "BODY[5.MIME]", Section: "5.MIME", Body: part5mime}}})

	part5text := "  ... Additional text in ISO-8859-1 goes here ...\r\n"
	tc.transactf("ok", "fetch 2 body.peek[5.text]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBody{RespAttr: "BODY[5.TEXT]", Section: "5.TEXT", Body: part5text}}})

	tc.transactf("ok", "fetch 2 body.peek[5.1]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{uid2, imapclient.FetchBody{RespAttr: "BODY[5.1]", Section: "5.1", Body: part5text}}})

	// In case of EXAMINE instead of SELECT, we should not be seeing any changed \Seen flags for non-peek commands.
	tc.client.StoreFlagsClear("1", true, `\Seen`)
	tc.client.Unselect()
	tc.client.Examine("inbox")

	tc.transactf("ok", "fetch 1 binary[]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, binary1}})

	tc.transactf("ok", "fetch 1 body[]")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, body1}})

	tc.transactf("ok", "fetch 1 rfc822.text")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, rfctext1}})

	tc.transactf("ok", "fetch 1 rfc822")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, rfc1}})

	tc.client.Logout()
}
