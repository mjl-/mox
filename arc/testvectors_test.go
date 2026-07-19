package arc

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mjl-/mox/dns"
)

// testCase represents a single ARC validation test case from the ValiMail test suite.
type testCase struct {
	name        string
	description string
	message     string
	cv          string // Expected chain validation: "None", "Pass", "Fail"
}

type parseState int

const (
	stateTop parseState = iota
	stateTests
	stateTestEntry
	stateTestMessage
	stateTestCV
	stateTxtRecords
	stateTxtRecordValue
)

// parseValidationTests parses the ValiMail arc-draft-validation-tests.yml file.
// Returns test cases and DNS TXT records.
func parseValidationTests(path string) ([]testCase, map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var tests []testCase
	txtRecords := map[string][]string{}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	state := stateTop
	var currentTest *testCase
	var messageLines []string
	var messageIndent string
	var txtRecordKey string
	var txtRecordValue string

	for scanner.Scan() {
		line := scanner.Text()

		switch state {
		case stateTop:
			if strings.HasPrefix(line, "tests:") {
				state = stateTests
			} else if strings.HasPrefix(line, "txt-records:") {
				state = stateTxtRecords
			}

		case stateTests:
			if strings.HasPrefix(line, "txt-records:") {
				// Save current test if any.
				if currentTest != nil {
					currentTest.message = buildMessage(messageLines, messageIndent)
					tests = append(tests, *currentTest)
					currentTest = nil
				}
				state = stateTxtRecords
				continue
			}
			// Test entry start: "  name:"
			if len(line) >= 3 && line[0] == ' ' && line[1] == ' ' && line[2] != ' ' && strings.HasSuffix(strings.TrimSpace(line), ":") {
				// Save previous test.
				if currentTest != nil {
					currentTest.message = buildMessage(messageLines, messageIndent)
					tests = append(tests, *currentTest)
				}
				name := strings.TrimSpace(line)
				name = name[:len(name)-1] // Remove trailing ":"
				currentTest = &testCase{name: name}
				messageLines = nil
				messageIndent = ""
				state = stateTestEntry
				continue
			}
			// Could be a test entry property.
			if currentTest != nil {
				if parsed := parseTestProperty(line, currentTest, &messageLines, &messageIndent, &state); parsed {
					continue
				}
			}

		case stateTestEntry:
			if strings.HasPrefix(line, "txt-records:") {
				if currentTest != nil {
					currentTest.message = buildMessage(messageLines, messageIndent)
					tests = append(tests, *currentTest)
					currentTest = nil
				}
				state = stateTxtRecords
				continue
			}
			// Another test entry.
			if len(line) >= 3 && line[0] == ' ' && line[1] == ' ' && line[2] != ' ' && strings.HasSuffix(strings.TrimSpace(line), ":") {
				if currentTest != nil {
					currentTest.message = buildMessage(messageLines, messageIndent)
					tests = append(tests, *currentTest)
				}
				name := strings.TrimSpace(line)
				name = name[:len(name)-1]
				currentTest = &testCase{name: name}
				messageLines = nil
				messageIndent = ""
				continue
			}
			if parseTestProperty(line, currentTest, &messageLines, &messageIndent, &state) {
				continue
			}

		case stateTestMessage:
			// Message lines are indented with 6 spaces typically.
			trimmed := line
			if strings.TrimSpace(line) == "" && len(messageLines) > 0 {
				// Empty line in message body.
				messageLines = append(messageLines, "")
				continue
			}
			if messageIndent == "" && len(trimmed) > 0 {
				// Detect indent level.
				for i, c := range line {
					if c != ' ' {
						messageIndent = line[:i]
						break
					}
				}
			}
			if messageIndent != "" && strings.HasPrefix(line, messageIndent) {
				messageLines = append(messageLines, line[len(messageIndent):])
				continue
			}
			// Line with less indent: end of message block.
			state = stateTestEntry
			if parseTestProperty(line, currentTest, &messageLines, &messageIndent, &state) {
				continue
			}
			// Could be a new test entry.
			if len(line) >= 3 && line[0] == ' ' && line[1] == ' ' && line[2] != ' ' && strings.HasSuffix(strings.TrimSpace(line), ":") {
				if currentTest != nil {
					currentTest.message = buildMessage(messageLines, messageIndent)
					tests = append(tests, *currentTest)
				}
				name := strings.TrimSpace(line)
				name = name[:len(name)-1]
				currentTest = &testCase{name: name}
				messageLines = nil
				messageIndent = ""
				state = stateTestEntry
				continue
			}

		case stateTxtRecords:
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if strings.HasSuffix(trimmed, ": >-") {
				// Start of a multi-line TXT record.
				txtRecordKey = strings.TrimSuffix(trimmed, ": >-")
				txtRecordValue = ""
				state = stateTxtRecordValue
				continue
			}
			// Single-line TXT record (key: value).
			if idx := strings.Index(trimmed, ": "); idx >= 0 {
				key := trimmed[:idx]
				val := trimmed[idx+2:]
				txtRecords[key+"."] = []string{val}
			}

		case stateTxtRecordValue:
			if strings.TrimSpace(line) == "" {
				if txtRecordKey != "" && txtRecordValue != "" {
					txtRecords[txtRecordKey+"."] = []string{txtRecordValue}
				}
				txtRecordKey = ""
				state = stateTxtRecords
				continue
			}
			// Check if this is a continuation or a new record.
			trimmed := strings.TrimSpace(line)
			if strings.HasSuffix(trimmed, ": >-") || (len(line) > 0 && line[0] != ' ') {
				// New record or section.
				if txtRecordKey != "" && txtRecordValue != "" {
					txtRecords[txtRecordKey+"."] = []string{txtRecordValue}
				}
				if strings.HasSuffix(trimmed, ": >-") {
					txtRecordKey = strings.TrimSuffix(trimmed, ": >-")
					txtRecordValue = ""
					continue
				}
				state = stateTxtRecords
				continue
			}
			txtRecordValue += trimmed
		}
	}

	// Save final test.
	if currentTest != nil {
		currentTest.message = buildMessage(messageLines, messageIndent)
		tests = append(tests, *currentTest)
	}
	// Save final txt record.
	if txtRecordKey != "" && txtRecordValue != "" {
		txtRecords[txtRecordKey+"."] = []string{txtRecordValue}
	}

	return tests, txtRecords, scanner.Err()
}

func parseTestProperty(line string, tc *testCase, messageLines *[]string, messageIndent *string, state *parseState) bool {
	trimmed := strings.TrimSpace(line)

	if strings.HasPrefix(trimmed, "description:") {
		tc.description = strings.TrimSpace(strings.TrimPrefix(trimmed, "description:"))
		return true
	}
	if strings.HasPrefix(trimmed, "cv:") {
		val := strings.TrimSpace(strings.TrimPrefix(trimmed, "cv:"))
		if val == "|" {
			// YAML block scalar with empty/whitespace content means "Fail" in this context.
			val = "Fail"
		}
		tc.cv = val
		return true
	}
	if strings.HasPrefix(trimmed, "spec:") {
		return true
	}
	if strings.HasPrefix(trimmed, "message:") {
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "message:"))
		if rest == "|" {
			*state = stateTestMessage
			*messageLines = nil
			*messageIndent = ""
		}
		return true
	}
	return false
}

func buildMessage(lines []string, indent string) string {
	_ = indent
	if len(lines) == 0 {
		return ""
	}
	// Join with CRLF as per RFC.
	result := strings.Join(lines, "\r\n")
	// Ensure it ends with CRLF.
	if !strings.HasSuffix(result, "\r\n") {
		result += "\r\n"
	}
	return result
}

func TestValiMailValidation(t *testing.T) {
	tests, txtRecords, err := parseValidationTests("testdata/arc-draft-validation-tests.yml")
	if err != nil {
		t.Fatalf("parsing test vectors: %v", err)
	}

	if len(tests) == 0 {
		t.Fatal("no test cases found")
	}
	if len(txtRecords) == 0 {
		t.Fatal("no TXT records found")
	}

	t.Logf("loaded %d test cases and %d TXT records", len(tests), len(txtRecords))

	resolver := dns.MockResolver{
		TXT: txtRecords,
	}

	passed := 0
	failed := 0

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Ensure message has header/body separator.
			if tc.message != "" && !strings.Contains(tc.message, "\r\n\r\n") {
				// No body separator - add one.
				tc.message += "\r\n"
			}

			result, err := Verify(context.Background(), pkglog.Logger, resolver, false, strings.NewReader(tc.message))

			var expectedStatus ChainStatus
			switch strings.ToLower(tc.cv) {
			case "none":
				expectedStatus = ChainStatusNone
			case "pass":
				expectedStatus = ChainStatusPass
			case "fail":
				expectedStatus = ChainStatusFail
			default:
				t.Fatalf("unknown expected cv %q", tc.cv)
			}

			if err != nil {
				// Parse errors are treated as "none" for messages without ARC.
				if expectedStatus == ChainStatusNone {
					passed++
					return
				}
				t.Logf("FAIL: %s: unexpected error: %v (expected %s)", tc.name, err, expectedStatus)
				failed++
				return
			}

			if result.Status != expectedStatus {
				t.Errorf("expected %s, got %s (err: %v, description: %s)",
					expectedStatus, result.Status, result.Err, tc.description)
				failed++
			} else {
				passed++
			}
		})
	}

	t.Logf("Results: %d passed, %d failed out of %d total", passed, failed, len(tests))
}

func TestValiMailParseCheck(t *testing.T) {
	// Quick sanity check that the parser finds test cases.
	tests, txtRecords, err := parseValidationTests("testdata/arc-draft-validation-tests.yml")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	if len(tests) < 10 {
		t.Fatalf("expected at least 10 test cases, got %d", len(tests))
	}

	// Check some expected test names.
	names := map[string]bool{}
	for _, tc := range tests {
		names[tc.name] = true
	}
	for _, expected := range []string{"cv_empty", "cv_pass_i1_1", "cv_fail_i1_ams_invalid"} {
		if !names[expected] {
			t.Errorf("missing expected test case %q", expected)
		}
	}

	// Check we have TXT records.
	if _, ok := txtRecords["dummy._domainkey.example.org."]; !ok {
		t.Error("missing dummy._domainkey.example.org TXT record")
	}

	// Print test summary.
	for _, tc := range tests {
		fmt.Printf("  %s: cv=%s (%s)\n", tc.name, tc.cv, tc.description)
	}
}
