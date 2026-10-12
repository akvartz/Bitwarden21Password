package migration

import (
	"encoding/json"
	"strconv"
)

// validateProviderOutput is an independent exact-value guard after strict
// parsing. It compares the private mapped projection with each emitted record,
// including record/array order, duplicate multiplicity and empty containers.
// It proves local writer fidelity, never provider acceptance or authentication.
func validateProviderOutput(mapped []mappedRecord, parsed *Document) error {
	invalid := &SafeError{Code: "output_validation"}
	if parsed == nil || parsed.provider == nil || parsed.inventory.Records != len(mapped) || len(parsed.provider.records) != len(mapped) {
		return invalid
	}
	switch parsed.format {
	case BitwardenJSON, OnePassword1PUX, ProtonPassZIP:
	default:
		return invalid
	}
	budget := MaxFields + MaxJSONContainers
	var identifiers map[string]int
	if parsed.format == OnePassword1PUX {
		identifiers = make(map[string]int, len(mapped))
		for _, record := range parsed.provider.records {
			if identifier, ok := record.value["uuid"].(string); ok {
				identifiers[identifier]++
			}
		}
	}
	for i, record := range mapped {
		if record.value == nil || parsed.provider.records[i].value == nil || !providerOutputValuesEqual(record.value, parsed.provider.records[i].value, parsed.format, i+1, providerOutputRecord, 0, &budget) {
			return invalid
		}
		if parsed.format == OnePassword1PUX {
			if _, explicit := record.value["uuid"]; !explicit {
				identifier, _ := parsed.provider.records[i].value["uuid"].(string)
				if identifiers[identifier] != 1 {
					return invalid
				}
			}
		}
	}
	return nil
}

type providerOutputScope uint8

const (
	providerOutputNoDefaults providerOutputScope = iota
	providerOutputRecord
	providerOutputOnePasswordOverview
)

func providerOutputValuesEqual(expected, actual any, format Format, record int, scope providerOutputScope, depth int, budget *int) bool {
	if depth > MaxJSONDepth || *budget <= 0 {
		return false
	}
	*budget--
	switch expected := expected.(type) {
	case map[string]any:
		actual, ok := actual.(map[string]any)
		if !ok {
			return false
		}
		// An empty container is a source value, not permission for new values.
		if len(expected) == 0 {
			return len(actual) == 0
		}
		for key, value := range expected {
			got, present := actual[key]
			if !present {
				return false
			}
			childScope := providerOutputNoDefaults
			if format == OnePassword1PUX && scope == providerOutputRecord && key == "overview" {
				childScope = providerOutputOnePasswordOverview
			}
			if !providerOutputValuesEqual(value, got, format, record, childScope, depth+1, budget) {
				return false
			}
		}
		for key, value := range actual {
			if _, present := expected[key]; !present {
				if !providerOutputDefault(format, record, scope, key, value) {
					return false
				}
			}
		}
		return true
	case []any:
		actual, ok := actual.([]any)
		if !ok || len(actual) != len(expected) {
			return false
		}
		for i, value := range expected {
			if !providerOutputValuesEqual(value, actual[i], format, record, providerOutputNoDefaults, depth+1, budget) {
				return false
			}
		}
		return true
	case nil:
		return actual == nil
	case string:
		got, ok := actual.(string)
		return ok && got == expected
	case bool:
		got, ok := actual.(bool)
		return ok && got == expected
	case json.Number:
		switch actual := actual.(type) {
		case json.Number:
			return actual.String() == expected.String()
		case int:
			return expected.String() == strconv.Itoa(actual)
		case int64:
			return expected.String() == strconv.FormatInt(actual, 10)
		default:
			return false
		}
	case int:
		switch actual := actual.(type) {
		case json.Number:
			return actual.String() == strconv.Itoa(expected)
		case int:
			return actual == expected
		case int64:
			return actual == int64(expected)
		default:
			return false
		}
	case int64:
		switch actual := actual.(type) {
		case json.Number:
			return actual.String() == strconv.FormatInt(expected, 10)
		case int:
			return int64(actual) == expected
		case int64:
			return actual == expected
		default:
			return false
		}
	default:
		return false
	}
}

// Only the writer's documented synthetic defaults may appear outside the
// projection, and only at these exact schema locations. Existing mapped keys
// always take the exact-value comparison above, including explicit nulls.
func providerOutputDefault(format Format, record int, scope providerOutputScope, key string, value any) bool {
	if format == OnePassword1PUX {
		if scope == providerOutputRecord {
			switch key {
			case "uuid":
				identifier, ok := value.(string)
				return ok && providerOutputGeneratedUUID(identifier)
			case "createdAt", "updatedAt", "favIndex":
				number, ok := value.(json.Number)
				return ok && number.String() == "0"
			case "state":
				state, ok := value.(string)
				return ok && state == "active"
			}
		}
		if scope == providerOutputOnePasswordOverview && (key == "subtitle" || key == "url") {
			text, ok := value.(string)
			return ok && text == ""
		}
	}
	if format == ProtonPassZIP && scope == providerOutputRecord {
		text, ok := value.(string)
		if !ok {
			return false
		}
		switch key {
		case "itemId":
			return text == "pwmigrate-item-"+strconv.Itoa(record)
		case "shareId":
			return text == "pwmigrate-vault-1"
		}
	}
	return false
}

func providerOutputGeneratedUUID(identifier string) bool {
	if len(identifier) != 26 {
		return false
	}
	for _, character := range identifier {
		if !((character >= 'a' && character <= 'z') || (character >= '2' && character <= '7')) {
			return false
		}
	}
	return true
}
