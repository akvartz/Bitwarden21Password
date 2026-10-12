package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"
	"unicode/utf8"

	"github.com/akvartz/Bitwarden21Password/internal/migration"
	"golang.org/x/term"
)

const passwordLineLimit = 16 << 10

func loadDocument(ctx context.Context, data []byte, source migration.Format, passwordStdin, passwordJSON bool, stdin io.Reader, stderr io.Writer) (*migration.Document, error) {
	document, err := migration.ParseWithPassword(data, source, nil)
	var safe *migration.SafeError
	if !errors.As(err, &safe) || safe.Code != "password_required" {
		return document, err
	}
	password, err := readLocalPassword(ctx, stdin, checkedWriter{stderr}, passwordStdin)
	if err != nil {
		return nil, err
	}
	defer clear(password)
	if passwordJSON {
		decoded, err := migration.DecodePasswordJSON(password)
		if err != nil {
			return nil, err
		}
		defer clear(decoded)
		password = decoded
	}
	return migration.ParseWithPassword(data, source, password)
}

type passwordResult struct {
	password []byte
	err      error
}

func readLocalPassword(ctx context.Context, stdin io.Reader, stderr io.Writer, fromStdin bool) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, &failure{"output_cancelled", 1}
	}
	if fromStdin {
		if stdin == nil {
			return nil, &failure{"password_required", 3}
		}
		result := make(chan passwordResult)
		go func() {
			password, err := readPasswordLine(ctx, stdin)
			select {
			case result <- passwordResult{password, err}:
			case <-ctx.Done():
				clear(password)
			}
		}()
		select {
		case <-ctx.Done():
			// The caller owns and must unblock a generic input reader. A result
			// produced after cancellation is cleared by readPasswordLine.
			return nil, &failure{"output_cancelled", 1}
		case received := <-result:
			if ctx.Err() != nil {
				clear(received.password)
				return nil, &failure{"output_cancelled", 1}
			}
			return received.password, received.err
		}
	}
	file, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil, &failure{"password_required", 3}
	}
	// Limit signal interception to the secret prompt. Read-only commands keep
	// default signal behavior while loading or writing their public reports.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	stderr = withWriteContext(ctx, stderr)
	password, err := readHiddenTerminalPassword(ctx, file, stderr)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		clear(password)
		return nil, &canceledReport{}
	}
	if _, err := io.WriteString(stderr, "\n"); err != nil {
		clear(password)
		if ctx.Err() != nil {
			return nil, &canceledReport{}
		}
		return nil, &failure{"output_write", 1}
	}
	if ctx.Err() != nil {
		clear(password)
		return nil, &canceledReport{}
	}
	return password, nil
}

func readHiddenTerminalPassword(ctx context.Context, file *os.File, stderr io.Writer) (password []byte, resultErr error) {
	fd := int(file.Fd())
	// Canonical terminal input can discard long passwords before ReadPassword
	// sees their bytes. Disable canonical processing before displaying the prompt
	// and enforce the full input bound ourselves with one-byte reads.
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, &failure{"password_read", 1}
	}
	defer func() {
		if err := term.Restore(fd, state); err != nil {
			clear(password)
			password, resultErr = nil, &failure{"password_read", 1}
			if ctx.Err() != nil {
				resultErr = &canceledReport{}
			}
		}
	}()
	if ctx.Err() != nil {
		return nil, &canceledReport{}
	}
	if _, err := io.WriteString(stderr, "Export password (input hidden): "); err != nil {
		if ctx.Err() != nil {
			return nil, &canceledReport{}
		}
		return nil, &failure{"output_write", 1}
	}
	if ctx.Err() != nil {
		return nil, &canceledReport{}
	}
	result := make(chan passwordResult)
	go func() {
		secret, err := readTerminalPasswordLine(ctx, file)
		select {
		case result <- passwordResult{secret, err}:
		case <-ctx.Done():
			clear(secret)
		}
	}()
	select {
	case <-ctx.Done():
		return nil, &canceledReport{}
	case received := <-result:
		if ctx.Err() != nil {
			clear(received.password)
			return nil, &canceledReport{}
		}
		var inputFailure *failure
		if errors.As(received.err, &inputFailure) && inputFailure.code == "output_cancelled" {
			clear(received.password)
			return nil, &canceledReport{}
		}
		return received.password, received.err
	}
}

func readTerminalPasswordLine(ctx context.Context, stdin io.Reader) ([]byte, error) {
	line := make([]byte, 0, 256)
	var one [1]byte
	emptyReads := 0
	for consumed := 0; consumed < passwordLineLimit; {
		if ctx.Err() != nil {
			clear(line)
			return nil, &failure{"output_cancelled", 1}
		}
		n, err := stdin.Read(one[:])
		if ctx.Err() != nil {
			clear(line)
			return nil, &failure{"output_cancelled", 1}
		}
		if n < 0 || n > 1 || (err != nil && err != io.EOF) {
			clear(line)
			return nil, &failure{"password_read", 1}
		}
		if n == 1 {
			consumed++
			switch one[0] {
			case '\r', '\n':
				if !utf8.Valid(line) {
					clear(line)
					return nil, &failure{"invalid_password", 3}
				}
				return line, nil
			case 3: // MakeRaw disables terminal-generated SIGINT.
				clear(line)
				return nil, &failure{"output_cancelled", 1}
			case 4:
				clear(line)
				return nil, &failure{"password_required", 3}
			case '\b', 127:
				if len(line) != 0 {
					_, size := utf8.DecodeLastRune(line)
					clear(line[len(line)-size:])
					line = line[:len(line)-size]
				}
			default:
				line = append(line, one[0])
			}
		}
		if err == io.EOF {
			clear(line)
			return nil, &failure{"password_required", 3}
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				clear(line)
				return nil, &failure{"password_read", 1}
			}
		} else {
			emptyReads = 0
		}
	}
	clear(line)
	return nil, &failure{"password_limit", 3}
}

func readPasswordLine(ctx context.Context, stdin io.Reader) ([]byte, error) {
	line := make([]byte, 0, 256)
	var one [1]byte
	emptyReads := 0
	for len(line) < passwordLineLimit {
		if ctx.Err() != nil {
			clear(line)
			return nil, &failure{"output_cancelled", 1}
		}
		n, err := stdin.Read(one[:])
		if ctx.Err() != nil {
			clear(line)
			return nil, &failure{"output_cancelled", 1}
		}
		if n < 0 || n > 1 || (err != nil && err != io.EOF) {
			clear(line)
			return nil, &failure{"password_read", 1}
		}
		if n == 1 {
			if one[0] == '\n' {
				if len(line) != 0 && line[len(line)-1] == '\r' {
					line = line[:len(line)-1]
				}
				return line, nil
			}
			line = append(line, one[0])
		}
		if err == io.EOF {
			clear(line)
			return nil, &failure{"password_required", 3}
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				clear(line)
				return nil, &failure{"password_read", 1}
			}
		} else {
			emptyReads = 0
		}
	}
	clear(line)
	return nil, &failure{"password_limit", 3}
}
