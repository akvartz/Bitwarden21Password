package migration

import "fmt"

// SafeError contains only a fixed code and optional one-based source ordinals.
type SafeError struct {
	Code           string
	Record, Column int
}

func (e *SafeError) Error() string {
	code := "invalid_input"
	if e == nil {
		return code
	}
	switch e.Code {
	case "unknown_format", "unsupported_encrypted", "unsupported_route",
		"invalid_utf8", "invalid_json", "duplicate_json_key", "invalid_csv",
		"duplicate_header", "empty_header", "missing_header", "uneven_row",
		"invalid_item", "invalid_selection", "input_limit", "record_limit",
		"field_limit", "depth_limit", "column_limit", "container_limit",
		"output_platform", "output_parent", "output_create", "output_write",
		"output_sync", "output_readback", "output_close", "output_publish",
		"output_cancelled", "approval_required", "approval_invalid",
		"invalid_state", "output_limit", "output_validation":
		code = e.Code
	}
	if e.Record > 0 && e.Column > 0 {
		return fmt.Sprintf("%s (record %d, column %d)", code, e.Record, e.Column)
	}
	if e.Record > 0 {
		return fmt.Sprintf("%s (record %d)", code, e.Record)
	}
	if e.Column > 0 {
		return fmt.Sprintf("%s (column %d)", code, e.Column)
	}
	return code
}
