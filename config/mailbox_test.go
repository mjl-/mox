package config

import "testing"

func TestCheckMailboxName(t *testing.T) {
	tests := []struct {
		name       string
		allowInbox bool
		want       string
		wantInbox  bool
		wantErr    bool
	}{
		{"Introbox", false, "Introbox", false, false},
		{"inbox/Intro", false, "Inbox/Intro", false, false},
		{"Inbox", true, "Inbox", false, false},
		{"Inbox", false, "", true, true},
		{"bad//name", false, "", false, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotInbox, err := CheckMailboxName(test.name, test.allowInbox)
			if (err != nil) != test.wantErr {
				t.Fatalf("CheckMailboxName error %v, want error %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("CheckMailboxName name %q, want %q", got, test.want)
			}
			if gotInbox != test.wantInbox {
				t.Fatalf("CheckMailboxName isInbox %v, want %v", gotInbox, test.wantInbox)
			}
		})
	}
}
