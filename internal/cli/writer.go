package cli

import (
	"bytes"
	"context"
	"io"
	"sync"
)

// canceledReport means no further diagnostic write may be attempted. A
// canceled or blocked stream cannot promise delivery of a final error line.
type canceledReport struct{}

func (*canceledReport) Error() string { return "output_cancelled" }

type reportWriteResult struct {
	n   int
	err error
}
type reportWriterState struct {
	mu       sync.Mutex
	writer   io.Writer
	pending  bool
	canceled bool
}
type contextReportWriter struct {
	ctx   context.Context
	state *reportWriterState
}

func withWriteContext(ctx context.Context, writer io.Writer) io.Writer {
	if ctx.Done() == nil {
		return writer
	}
	switch writer := writer.(type) {
	case checkedWriter:
		return checkedWriter{withWriteContext(ctx, writer.Writer)}
	case *contextReportWriter:
		// Prompt-local and command-wide contexts share one physical writer.
		return &contextReportWriter{ctx: ctx, state: writer.state}
	default:
		return &contextReportWriter{ctx: ctx, state: &reportWriterState{writer: writer}}
	}
}

func (w *contextReportWriter) Write(data []byte) (int, error) {
	s := w.state
	s.mu.Lock()
	if w.ctx.Err() != nil || s.canceled {
		s.canceled = true
		s.mu.Unlock()
		return 0, &canceledReport{}
	}
	if s.pending {
		s.mu.Unlock()
		return 0, io.ErrShortWrite
	}
	s.pending = true
	// fmt and JSON encoders may recycle their buffers as soon as Write returns.
	// The pending physical write owns this copy until the caller unblocks it.
	owned := bytes.Clone(data)
	result := make(chan reportWriteResult, 1)
	go func() {
		n, err := s.writer.Write(owned)
		s.mu.Lock()
		s.pending = false
		s.mu.Unlock()
		result <- reportWriteResult{n, err}
	}()
	s.mu.Unlock()
	markCanceled := func() (int, error) {
		s.mu.Lock()
		s.canceled = true
		s.mu.Unlock()
		return 0, &canceledReport{}
	}
	select {
	case <-w.ctx.Done():
		return markCanceled()
	case received := <-result:
		if w.ctx.Err() != nil {
			return markCanceled()
		}
		if received.n < 0 || received.n > len(data) {
			return 0, io.ErrShortWrite
		}
		return received.n, received.err
	}
}
