package cli

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

type blockedReportWriter struct {
	started  chan struct{}
	release  chan struct{}
	finished chan struct{}
	mu       sync.Mutex
	writes   int
	snapshot []byte
}

func (w *blockedReportWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.writes++
	first := w.writes == 1
	w.mu.Unlock()
	if first {
		close(w.started)
	}
	<-w.release
	w.mu.Lock()
	w.snapshot = append([]byte{}, p...)
	w.mu.Unlock()
	if first {
		close(w.finished)
	}
	return len(p), nil
}

func TestCanceledReportOwnsPendingBufferAndNeverWritesAgain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	underlying := &blockedReportWriter{started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	writer := withWriteContext(ctx, underlying)
	data := []byte("safe redacted report bytes")
	result := make(chan error, 1)
	go func() { _, err := writer.Write(data); result <- err }()
	select {
	case <-underlying.started:
	case <-time.After(time.Second):
		t.Fatal("report write did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil || err.Error() != "output_cancelled" {
			t.Fatal("blocked report did not return safe cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("report cancellation blocked")
	}
	for i := range data {
		data[i] = 'x'
	}
	if _, err := writer.Write([]byte("must not write")); err == nil {
		t.Fatal("canceled report wrapper accepted another write")
	}
	underlying.mu.Lock()
	writes := underlying.writes
	underlying.mu.Unlock()
	if writes != 1 {
		t.Fatal("cancellation started an extra report write")
	}
	close(underlying.release)
	select {
	case <-underlying.finished:
	case <-time.After(time.Second):
		t.Fatal("caller could not unblock report writer")
	}
	underlying.mu.Lock()
	snapshot := string(underlying.snapshot)
	underlying.mu.Unlock()
	if snapshot != "safe redacted report bytes" {
		t.Fatal("pending report borrowed a reused caller buffer")
	}
}

func TestContextReportViewsShareOnePendingWrite(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	underlying := &blockedReportWriter{started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	writer := withWriteContext(parent, underlying)
	local, stop := context.WithCancel(parent)
	defer stop()
	view := withWriteContext(local, checkedWriter{writer})
	result := make(chan error, 1)
	go func() { _, err := view.Write([]byte("safe prompt")); result <- err }()
	<-underlying.started
	stop()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("local report cancellation blocked")
	}
	if _, err := writer.Write([]byte("must not write")); err == nil {
		t.Fatal("parent report view started a write after local cancellation")
	}
	underlying.mu.Lock()
	writes := underlying.writes
	underlying.mu.Unlock()
	if writes != 1 {
		t.Fatal("context report views nested or overlapped writes")
	}
	close(underlying.release)
	<-underlying.finished
}

func TestBackgroundReportWriterRemainsSynchronous(t *testing.T) {
	underlying := failingWriter{short: true}
	writer := withWriteContext(context.Background(), underlying)
	if _, asynchronous := writer.(*contextReportWriter); asynchronous {
		t.Fatal("background report writer introduced a goroutine boundary")
	}
	if _, err := (checkedWriter{writer}).Write([]byte("safe")); err != io.ErrShortWrite {
		t.Fatal("synchronous report short-write behavior changed")
	}
}
