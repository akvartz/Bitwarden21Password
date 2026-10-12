package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akvartz/Bitwarden21Password/internal/protectedoutput"
	"github.com/akvartz/Bitwarden21Password/internal/recovery"
)

func TestRecoveryJobRequiresWholeSourceAcknowledgmentAndRecoversExcludedRecords(t *testing.T) {
	if !protectedoutput.Supported() {
		t.Skip("native writer qualification absent")
	}
	source := []byte("name,url,username,password\nSYNTHETIC_ONE,u,a, exact \nSYNTHETIC_EXCLUDED,v,b, second \n")
	d := mustParse(t, source, ChromeCSV)
	identity, err := recovery.GenerateIdentity()
	if err != nil {
		t.Fatal("identity generation")
	}
	parent := t.TempDir()
	if os.Chmod(parent, 0700) != nil {
		t.Fatal("parent privacy")
	}
	j, err := d.NewJobWithRecovery(BitwardenJSON, []int{1}, parent, identity)
	if err != nil {
		t.Fatal(err)
	}
	r := j.Review()
	ids := []string{}
	retention := false
	for _, issue := range r.Issues {
		ids = append(ids, issue.ID)
		if issue.ID == "recovery-whole-source" {
			retention = true
		}
	}
	if !retention {
		t.Fatal("whole-source recovery not acknowledged")
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "SYNTHETIC") || bytes.Contains(raw, identity) {
		t.Fatal("secret leaked")
	}
	if err := j.Approve(r.ReviewID, ids); err != nil {
		t.Fatal(err)
	}
	receipt, err := j.Commit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RecoveryFileName != "recovery.age" || receipt.RecoveryJobDirectory == "" {
		t.Fatal("recovery completion missing")
	}
	ciphertext, err := os.ReadFile(filepath.Join(parent, receipt.RecoveryJobDirectory, receipt.RecoveryFileName))
	if err != nil {
		t.Fatal("recovery output missing")
	}
	payload, err := recovery.Decrypt(ciphertext, identity)
	if err != nil || payload.Format != string(ChromeCSV) || !bytes.Equal(payload.Source, source) {
		t.Fatal("whole source recovery changed")
	}
	if _, err := j.Commit(context.Background()); err == nil {
		t.Fatal("recovery approval replay accepted")
	}
}
