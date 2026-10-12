package migration

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

func (d *Document) selectedOrdinals(selection []int) ([]int, error) {
	if d == nil {
		return nil, &SafeError{Code: "invalid_selection"}
	}
	total := d.inventory.Records
	if selection == nil {
		selected := make([]int, total)
		for i := range selected {
			selected[i] = i + 1
		}
		return selected, nil
	}
	if len(selection) == 0 || len(selection) > total {
		return nil, &SafeError{Code: "invalid_selection"}
	}
	selected := append([]int{}, selection...)
	sort.Ints(selected)
	for i, v := range selected {
		if v < 1 || v > total || (i > 0 && v == selected[i-1]) {
			return nil, &SafeError{Code: "invalid_selection"}
		}
	}
	return selected, nil
}

func providerRoute(source, target Format) bool {
	return source != target && (source == BitwardenJSON || source == OnePassword1PUX || source == ProtonPassZIP) && (target == BitwardenJSON || target == OnePassword1PUX || target == ProtonPassZIP)
}

func (d *Document) mappedItems(target Format, selected []int) ([]mappedRecord, error) {
	if d == nil {
		return nil, &SafeError{Code: "unsupported_route"}
	}
	selected, err := d.selectedOrdinals(selected)
	if err != nil {
		return nil, err
	}
	if IsBrowserFormat(d.format) {
		if target != BitwardenJSON && target != OnePassword1PUX && target != ProtonPassZIP {
			return nil, &SafeError{Code: "unsupported_route"}
		}
		payload, err := exportChrome(d, selected)
		if err != nil {
			return nil, err
		}
		parsed, err := Parse(payload, BitwardenJSON)
		if err != nil {
			return nil, err
		}
		plan, err := d.planCSV(BitwardenJSON, selectedOrNil(selected))
		if err != nil {
			return nil, err
		}
		out := make([]mappedRecord, len(selected))
		for i := range selected {
			out[i] = mappedRecord{value: parsed.provider.records[i].value, mappings: map[string]fieldMapping{}}
			for _, f := range plan.Fields[i*len(d.chromeHeaders) : (i+1)*len(d.chromeHeaders)] {
				out[i].mappings["/"+strconv.Itoa(f.Field-1)] = fieldMapping{disposition: f.Disposition, target: f.TargetField, concealed: f.Concealed}
			}
			if target != BitwardenJSON {
				second, err := mapProviderRecord(BitwardenJSON, target, parsed.provider.records[i])
				if err != nil {
					return nil, err
				}
				fields := make([]sourceField, len(d.chromeHeaders))
				for column := range fields {
					fields[column].path = "/" + strconv.Itoa(column)
				}
				out[i] = composeProviderMapping(out[i], second, fields)
			}
		}
		return out, nil
	}
	if !providerRoute(d.format, target) || d.provider == nil {
		return nil, &SafeError{Code: "unsupported_route"}
	}
	out := make([]mappedRecord, 0, len(selected))
	for _, ordinal := range selected {
		record := d.provider.records[ordinal-1]
		mapped, err := mapProviderRecord(d.format, target, record)
		if err != nil {
			return nil, err
		}
		if mapped.mappings == nil {
			mapped.mappings = map[string]fieldMapping{}
		}
		for _, field := range record.fields {
			if _, ok := mapped.mappings[field.path]; !ok {
				mapped.mappings[field.path] = fieldMapping{disposition: "unsupported"}
			}
		}
		out = append(out, mapped)
	}
	return out, nil
}

func selectedOrNil(selected []int) []int {
	if len(selected) == 0 {
		return nil
	}
	return selected
}

func mapProviderRecord(source, target Format, record providerRecord) (mappedRecord, error) {
	switch {
	case source == BitwardenJSON && target == OnePassword1PUX:
		return mapBitwardenToOnePassword(record)
	case source == OnePassword1PUX && target == BitwardenJSON:
		return mapOnePasswordToBitwarden(record)
	case source == BitwardenJSON && target == ProtonPassZIP:
		return mapBitwardenToProton(record)
	case source == ProtonPassZIP && target == BitwardenJSON:
		return mapProtonToBitwarden(record)
	}
	// Two-step provider routes conservatively account for intermediary losses.
	first, err := mapProviderRecord(source, BitwardenJSON, record)
	if err != nil || first.value == nil {
		return first, err
	}
	mid := providerRecord{value: first.value, kind: record.kind, fields: flattenFields(first.value, "")}
	second, err := mapProviderRecord(BitwardenJSON, target, mid)
	if err != nil {
		return mappedRecord{}, err
	}
	return composeProviderMapping(first, second, record.fields), nil
}

func composeProviderMapping(first, second mappedRecord, fields []sourceField) mappedRecord {
	result := mappedRecord{value: second.value, mappings: map[string]fieldMapping{}, issues: append(append([]string{}, first.issues...), second.issues...)}
	result.issues = append(result.issues, "intermediary_mapping")
	// Index exact and schema-level prefixes once; broad custom-field schema
	// paths conservatively combine every represented descendant's disposition.
	index := mappingPrefixIndex(second.mappings)
	for _, field := range fields {
		mapping, ok := first.mappings[field.path]
		if !ok {
			mapping = fieldMapping{disposition: "unsupported"}
		}
		if mapping.disposition == "unsupported" || mapping.disposition == "omitted" {
			result.mappings[field.path] = mapping
			continue
		}
		pointer := mapping.target
		if !strings.HasPrefix(pointer, "/") {
			pointer = "/" + strings.NewReplacer(".", "/", "[", "/", "]", "").Replace(pointer)
		}
		pointers := []string{pointer}
		if pointer == "/card/expMonth_and_expYear" {
			pointers = []string{"/card/expMonth", "/card/expYear"}
		}
		supported := true
		for _, path := range pointers {
			unsupported, observed := index[path]
			if !observed || unsupported {
				supported = false
			}
		}
		if !supported {
			mapping = fieldMapping{disposition: "unsupported"}
		} else {
			mapping = fieldMapping{disposition: "transformed", target: "provider_item", concealed: mapping.concealed}
		}
		result.mappings[field.path] = mapping
	}
	return result
}

func mappingPrefixIndex(mappings map[string]fieldMapping) map[string]bool {
	index := make(map[string]bool, len(mappings))
	for path, mapping := range mappings {
		bad := mapping.disposition == "unsupported" || mapping.disposition == "omitted"
		segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
		exact, canonical := "", ""
		for _, segment := range segments {
			exact += "/" + segment
			index[exact] = index[exact] || bad
			if _, err := strconv.Atoi(segment); err != nil {
				canonical += "/" + segment
				index[canonical] = index[canonical] || bad
			}
		}
	}
	return index
}

func (d *Document) planProvider(target Format, selection []int) (Plan, error) {
	if !providerRoute(d.format, target) || d.provider == nil {
		return Plan{}, &SafeError{Code: "unsupported_route"}
	}
	selected, err := d.selectedOrdinals(selection)
	if err != nil {
		return Plan{}, err
	}
	mapped, err := d.mappedItems(target, selectedOrNil(selected))
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Source: d.format, Target: target, State: "planned", TotalRecords: d.inventory.Records, SelectedRecords: len(selected), ExcludedRecords: d.inventory.Records - len(selected), Fields: []FieldDisposition{}, DuplicateGroups: selectedProviderDuplicateGroups(d.inventory.DuplicateGroups, selected, d.inventory.Records), Caveats: append([]string{}, d.inventory.Caveats...)}
	plan.Caveats = append(plan.Caveats, "planned_only_no_output", "destination_import_not_verified", "provider_metadata_not_migrated")
	for i, ordinal := range selected {
		for j, field := range d.provider.records[ordinal-1].fields {
			mapping := mapped[i].mappings[field.path]
			switch mapping.disposition {
			case "native", "relocated", "transformed", "unsupported", "omitted":
			default:
				return Plan{}, &SafeError{Code: "output_validation"}
			}
			plan.Fields = append(plan.Fields, FieldDisposition{Record: ordinal, Field: j + 1, Disposition: mapping.disposition, TargetField: mapping.target, Concealed: mapping.concealed})
		}
	}
	for i := range d.provider.metadata {
		plan.Metadata = append(plan.Metadata, FieldDisposition{Field: i + 1, Disposition: "unsupported"})
	}
	return plan, nil
}

// marshalBounded checks string escaping and total output before allocating a
// large marshaled representation; JSON numbers retain their original tokens.
func marshalBounded(value any) ([]byte, error) {
	var b outputBuffer
	var encode func(any)
	encode = func(value any) {
		if b.err != nil {
			return
		}
		switch v := value.(type) {
		case map[string]any:
			b.literal("{")
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for i, key := range keys {
				if i != 0 {
					b.literal(",")
				}
				b.text(key)
				b.literal(":")
				encode(v[key])
			}
			b.literal("}")
		case []any:
			b.literal("[")
			for i, child := range v {
				if i != 0 {
					b.literal(",")
				}
				encode(child)
			}
			b.literal("]")
		case string:
			b.text(v)
		case json.Number:
			if !json.Valid([]byte(v.String())) {
				b.err = &SafeError{Code: "output_validation"}
				return
			}
			b.literal(v.String())
		case int:
			b.literal(strconv.Itoa(v))
		case int64:
			b.literal(strconv.FormatInt(v, 10))
		case bool:
			if v {
				b.literal("true")
			} else {
				b.literal("false")
			}
		case nil:
			b.literal("null")
		default:
			b.err = &SafeError{Code: "output_validation"}
		}
	}
	encode(value)
	if b.err != nil {
		return nil, b.err
	}
	return b.data, nil
}

func (d *Document) exportProvider(target Format, selected []int) ([]byte, error) {
	mapped, err := d.mappedItems(target, selectedOrNil(selected))
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(mapped))
	for _, record := range mapped {
		if record.value == nil {
			return nil, &SafeError{Code: "unsupported_route"}
		}
		items = append(items, record.value)
	}
	var payload []byte
	switch target {
	case BitwardenJSON:
		values := make([]any, len(items))
		for i, item := range items {
			values[i] = item
		}
		payload, err = marshalBounded(map[string]any{"encrypted": false, "folders": []any{}, "items": values})
	case OnePassword1PUX:
		payload, err = exportOnePassword(items)
	case ProtonPassZIP:
		payload, err = exportProton(items)
	default:
		return nil, &SafeError{Code: "unsupported_route"}
	}
	if err != nil {
		return nil, err
	}
	if len(payload) > maxOutputBytes {
		return nil, &SafeError{Code: "output_limit"}
	}
	// Strict generated-output schema/limits, separate from provider acceptance.
	parsed, err := Parse(payload, target)
	if err != nil || parsed.inventory.Records != len(items) {
		return nil, &SafeError{Code: "output_validation"}
	}
	if err := validateProviderOutput(mapped, parsed); err != nil {
		return nil, err
	}
	return payload, nil
}
