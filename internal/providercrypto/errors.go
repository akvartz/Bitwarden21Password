// Package providercrypto unlocks explicitly supported provider export profiles.
package providercrypto

// Error contains only a fixed safe code, never source data or a crypto error.
type Error struct {
	Code string
}

func (e *Error) Error() string {
	if e == nil {
		return "invalid_encrypted"
	}
	switch e.Code {
	case "unsupported_encrypted", "unsupported_kdf", "kdf_limit", "invalid_encrypted", "authentication_failed", "input_limit":
		return e.Code
	default:
		return "invalid_encrypted"
	}
}
