package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func cliEncryptedVectors(t *testing.T) []struct {
	Password string
	Envelope json.RawMessage
} {
	t.Helper()
	fixture, err := os.ReadFile("../providercrypto/testdata/bitwarden-vectors.json")
	if err != nil {
		t.Fatal("independent fixture unavailable")
	}
	var vectors []struct {
		Password string
		Envelope json.RawMessage
	}
	if json.Unmarshal(fixture, &vectors) != nil || len(vectors) != 2 {
		t.Fatal("independent fixture invalid")
	}
	return vectors
}

func TestEncryptedInspectJSONPasswordPreservesExactBytes(t *testing.T) {
	for _, vector := range cliEncryptedVectors(t) {
		path := inputFixture(t, string(vector.Envelope))
		password, err := json.Marshal(vector.Password)
		if err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := RunContext(context.Background(), []string{"inspect", "--input", path, "--password-stdin", "--password-json", "--json"}, strings.NewReader(string(password)+"\n"), &stdout, &stderr)
		if code != 0 || stderr.Len() != 0 {
			t.Fatal("independent encrypted fixture could not unlock through JSON secret framing")
		}
		var got struct {
			Format  string   `json:"format"`
			Records int      `json:"records"`
			Caveats []string `json:"caveats"`
		}
		if json.Unmarshal(stdout.Bytes(), &got) != nil || got.Format != "bitwarden-json" || got.Records != 0 {
			t.Fatal("encrypted inspection returned wrong inventory")
		}
		if strings.Contains(stdout.String(), vector.Password) || strings.Contains(stdout.String(), path) {
			t.Fatal("encrypted inspection leaked password or path")
		}
	}
}

func TestEncryptedInputRequiresSecretChannelAndRejectsWrongPasswordSafely(t *testing.T) {
	vector := cliEncryptedVectors(t)[0]
	path := inputFixture(t, string(vector.Envelope))
	for _, tc := range []struct {
		args  []string
		stdin string
		exit  int
		code  string
	}{
		{nil, vector.Password + "\n", 3, "password_required"},
		{[]string{"--password-stdin", "--password-json"}, `"wrong synthetic password"` + "\n", 3, "authentication_failed"},
		{[]string{"--password-stdin", "--password-json"}, `{"secret":"do not echo"}` + "\n", 3, "invalid_password"},
		{[]string{"--password-json"}, "", 2, "invalid_arguments"},
	} {
		var stdout, stderr bytes.Buffer
		args := append([]string{"inspect", "--input", path}, tc.args...)
		code := RunContext(context.Background(), args, strings.NewReader(tc.stdin), &stdout, &stderr)
		if code != tc.exit || stdout.Len() != 0 || stderr.String() != tc.code+"\n" {
			t.Fatal("secret-channel rejection did not use fixed code")
		}
	}
}

func TestEncryptedConvertConsumesPasswordThenExactApproval(t *testing.T) {
	requireLinuxOutput(t)
	vector := cliEncryptedVectors(t)[0]
	path := inputFixture(t, string(vector.Envelope))
	parent := privateOutputParent(t)
	password, err := json.Marshal(vector.Password)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	approval := &promptReply{prompt: &stderr}
	stdin := io.MultiReader(strings.NewReader(string(password)+"\n"), approval)
	args := []string{"convert", "--input", path, "--to", "onepassword-1pux", "--output-dir", parent, "--password-stdin", "--password-json", "--json"}
	if code := RunContext(context.Background(), args, stdin, &stdout, &stderr); code != 0 {
		t.Fatal("secret framing consumed or changed conversion approval")
	}
	events := decodeEvents(t, stdout.String())
	if len(events) != 2 || events[0].Event != "review" || events[1].Event != "completed" || events[1].Receipt.FileName != "onepassword.1pux" {
		t.Fatal("encrypted conversion did not complete exact one-shot protocol")
	}
	if strings.Contains(stdout.String()+stderr.String(), vector.Password) || strings.Contains(stdout.String()+stderr.String(), "AGE-SECRET-KEY") {
		t.Fatal("conversion reported a secret")
	}
}

func TestPasswordReadPreservesWhitespaceAndLeavesApprovalUnread(t *testing.T) {
	reader := strings.NewReader("  exact secret  \r\napprove untouched\n")
	got, err := readPasswordLine(context.Background(), reader)
	if err != nil || string(got) != "  exact secret  " {
		t.Fatal("plain password framing normalized spaces")
	}
	remaining, err := io.ReadAll(reader)
	if err != nil || string(remaining) != "approve untouched\n" {
		t.Fatal("password read buffered approval bytes")
	}
}

func TestPasswordReadCancellationRetainsCallerOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &blockedApproval{started: make(chan struct{}), release: make(chan struct{})}
	defer close(reader.release)
	result := make(chan error, 1)
	go func() { _, err := readLocalPassword(ctx, reader, io.Discard, true); result <- err }()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("secret read did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil || err.Error() != "output_cancelled" || reader.closed {
			t.Fatal("secret cancellation failed or closed caller input")
		}
	case <-time.After(time.Second):
		t.Fatal("secret cancellation blocked")
	}
}

func TestTerminalPasswordLineFramesExactBytesAndEditsRunes(t *testing.T) {
	for _, tc := range []struct{ input, want, remaining, code string }{
		{"  exact secret  \nnext", "  exact secret  ", "next", ""},
		{"  exact secret  \rnext", "  exact secret  ", "next", ""},
		{"  exact secret  \r\nnext", "  exact secret  ", "\nnext", ""},
		{" e\u0301Ω🙂\x7f\x08Z \rnext", " e\u0301Z ", "next", ""},
		{"e\u0301\x7f\nnext", "e", "next", ""},
		{"\x08\x7f\nnext", "", "next", ""},
		{"secret\x03next", "", "next", "output_cancelled"},
		{"secret\x04next", "", "next", "password_required"},
		{string([]byte{0xc3, '\n'}) + "next", "", "next", "invalid_password"},
	} {
		reader := strings.NewReader(tc.input)
		password, err := readTerminalPasswordLine(context.Background(), reader)
		if tc.code == "" {
			if err != nil || password == nil || string(password) != tc.want {
				t.Fatal("terminal framing changed exact values or rune editing")
			}
		} else if err == nil || err.Error() != tc.code || password != nil {
			t.Fatal("terminal framing returned a partial secret after failure")
		}
		remaining, err := io.ReadAll(reader)
		if err != nil || string(remaining) != tc.remaining {
			t.Fatal("terminal framing consumed input beyond first delimiter/control event")
		}
	}
}
