package store

import (
	"fmt"
	"testing"
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
