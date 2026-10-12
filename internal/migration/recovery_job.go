package migration

import (
	"bytes"
	"context"
	"errors"

	"github.com/akvartz/Bitwarden21Password/internal/protectedoutput"
	"github.com/akvartz/Bitwarden21Password/internal/recovery"
)

// NewJobWithRecovery binds a whole-source recovery artifact into the same
// one-shot approval. Excluded source records also remain in the encrypted copy.
func (d *Document) NewJobWithRecovery(target Format, selection []int, parent string, identity []byte) (*Job, error) {
	job, err := d.NewJob(target, selection, parent)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return job, nil
	}
	ciphertext, err := recovery.Encrypt(string(d.format), d.original, identity)
	if err != nil {
		return nil, recoveryFailure(err)
	}
	decoded, err := recovery.Decrypt(ciphertext, identity)
	if err != nil || decoded.Format != string(d.format) || !bytes.Equal(decoded.Source, d.original) {
		return nil, &SafeError{Code: "output_validation"}
	}
	clear(decoded.Source)
	p := job.private
	p.review.Issues = append(p.review.Issues, Issue{ID: "recovery-whole-source", Code: "recovery_whole_source", Records: d.inventory.Records})
	p.review.Plan.Caveats = append(p.review.Plan.Caveats, "recovery_preserves_whole_source_not_destination_success", "recovery_key_required", "failed_jobs_may_retain_private_artifacts")
	write := p.writeOutput
	p.writeOutput = func(ctx context.Context, parent string, payload []byte) (protectedoutput.Result, error) {
		result, err := write(ctx, parent, payload)
		if err != nil {
			return protectedoutput.Result{}, err
		}
		if ctx.Err() != nil {
			return protectedoutput.Result{}, &protectedoutput.Error{Code: "output_cancelled"}
		}
		recovered, err := protectedoutput.WriteNamed(ctx, parent, "recovery.age", ciphertext)
		if err != nil {
			return protectedoutput.Result{}, err
		}
		p.mu.Lock()
		p.recoveryResult = recovered
		p.mu.Unlock()
		return result, nil
	}
	return job, nil
}

func recoveryFailure(err error) error {
	var safe *recovery.Error
	if errors.As(err, &safe) {
		return &SafeError{Code: safe.Error()}
	}
	return &SafeError{Code: "output_validation"}
}
