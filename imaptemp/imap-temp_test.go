/*
Written 2024 by Harald Rudell <harald.rudell@gmail.com> (https://haraldrudell.github.io/haraldrudell/)
*/

package imaptemp

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

func TestImapTemp(t *testing.T) {
	//t.Errorf("logging on")

	// expected prefix of the greeting “* OK”
	var prefixExp = "* OK "
	// expected suffix of the greeting “mox imap\r\n”
	var suffixExp = "mox imap\r\n"
	// the greeting ends with the newline byte
	const newLine = '\n'

	var imapTemp *ImapTemp
	var err error
	var imapConn net.Conn
	var lineReader *bufio.Reader
	var line []byte

	imapTemp = NewImapTemp()

	imapConn, err = imapTemp.CreateSocket()
	defer closeImapTemp(imapTemp, t)

	// CreateSocket should succeed
	if err != nil {
		t.Errorf("CreateSocket err: %q", err)
		return
	}

	// IMAP4rev2 server should output a greeting
	//	- read until first newline, unlimited length, no timeout
	lineReader = bufio.NewReader(imapConn)
	if line, err = lineReader.ReadBytes(newLine); err != nil {
		t.Errorf("ReadBytes err: %q", err)
		return
	}

	// line: "* OK [CAPABILITY
	// IMAP4rev2 IMAP4rev1 ENABLE LITERAL+
	// IDLE SASL-IR BINARY UNSELECT UIDPLUS ESEARCH SEARCHRES
	// MOVE UTF8=ACCEPT LIST-EXTENDED SPECIAL-USE LIST-STATUS
	// AUTH=SCRAM-SHA-256-PLUS AUTH=SCRAM-SHA-256
	// AUTH=SCRAM-SHA-1-PLUS AUTH=SCRAM-SHA-1 AUTH=CRAM-MD5
	// ID APPENDLIMIT=9223372036854775807 CONDSTORE QRESYNC
	// STATUS=SIZE AUTH=PLAIN
	// ] mox imap\r\n"
	t.Logf("line: %q", line)

	// greeting should contain OK and mox
	if !bytes.HasPrefix(line, []byte(prefixExp)) || !bytes.HasSuffix(line, []byte(suffixExp)) {
		t.Errorf("FAIL bad greeting from mox: prefixExp: %q suffixExp %q greeting:\n%s",
			prefixExp, suffixExp, line,
		)
	}
}

// closeImapTemp is a deferrable function closing imapTemp
func closeImapTemp(imapTemp *ImapTemp, t *testing.T) {
	var err = imapTemp.Close()
	if err != nil {
		t.Errorf("FAIL imapTemp.Close err: %q", err)
	}
}
