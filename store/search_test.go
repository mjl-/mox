package store

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
)

func TestSubjectMatch(t *testing.T) {
	// Auto detect subject text encoding and decode

	//log := mlog.New("search", nil)

	originalSubject := `テストテキスト Abc 123...`
	asciiSubject := "test text Abc 123..."

	encodedSubjectUTF8 := `=?UTF-8?b?44OG44K544OI44OG44Kt44K544OIIEFiYyAxMjMuLi4=?=`
	encodedSubjectISO2022 := `=?iso-2022-jp?B?GyRCJUYlOSVIJUYlLSU5JUgbKEIgQWJjIDEyMy4uLg==?=`
	encodedSubjectUTF8 = encodedSubjectUTF8 + " \n " + encodedSubjectUTF8
	encodedSubjectISO2022 = encodedSubjectISO2022 + " \n " + encodedSubjectISO2022
	originalSubject = originalSubject + originalSubject

	encodedTexts := map[string]string{encodedSubjectUTF8: originalSubject, encodedSubjectISO2022: originalSubject, asciiSubject: asciiSubject}

	for encodedSubject, originalSubject := range encodedTexts {

		// Autodetect & decode
		decodedSubject, err := decodeRFC2047(encodedSubject)

		fmt.Printf("decoded text:%s\n", decodedSubject)
		if err != nil {
			t.Fatalf("Decode error: %v", err)
		}

		if originalSubject != decodedSubject {
			t.Fatalf("Decode mismatch %s != %s", originalSubject, decodedSubject)
		}
	}
}

func TestMultipartMailDecode(t *testing.T) {
	log := mlog.New("search", nil)

	// Load raw mail file
	filePath := "../../data/mail_raw.txt" // multipart mail raw data
	wordFilePath := "../../data/word.txt"

	msgFile, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer msgFile.Close()

	// load word
	wordFile, err := os.Open(wordFilePath)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer wordFile.Close()
	tmp, err := io.ReadAll(wordFile)
	if err != nil {
		t.Fatalf("Failed to load search word: %v", err)
	}
	searchWord := strings.TrimSpace(string(tmp))

	// Parse mail
	mr := FileMsgReader([]byte{}, msgFile)
	p, err := message.Parse(log.Logger, false, mr)
	if err != nil {
		t.Fatalf("parsing message for evaluating rulesets, continuing with headers %v, %s", err, slog.String("parse", ""))
	}

	// Match
	ws := PrepareWordSearch([]string{searchWord}, []string{})
	ok, _ := ws.MatchPart(log, &p, true)
	if !ok {
		t.Fatalf("Match failed %s", ws.words)
	}
	log.Debug("Check match", slog.String("word", string(searchWord)), slog.Bool("ok", ok))
}
