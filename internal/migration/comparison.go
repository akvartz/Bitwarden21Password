package migration

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Comparison describes observations from a caller-supplied destination export.
// It contains only fixed codes, counts, and one-based ordinals. It does not
// establish that a provider accepted generated output or that passkeys function.
type Comparison struct {
	Source                        Format            `json:"source"`
	Target                        Format            `json:"target"`
	State                         string            `json:"state"`
	ExpectedRecords               int               `json:"expected_records"`
	DestinationRecords            int               `json:"destination_records"`
	MatchedRecords                int               `json:"matched_records"`
	MissingRecords                int               `json:"missing_records"`
	UnexpectedRecords             int               `json:"unexpected_records"`
	Groups                        []ComparisonGroup `json:"groups"`
	SourceUnobservableFields      []ComparisonField `json:"source_unobservable_fields"`
	DestinationUnobservableFields []ComparisonField `json:"destination_unobservable_fields"`
	SourceMetadataFields          int               `json:"source_metadata_fields"`
	DestinationMetadataFields     int               `json:"destination_metadata_fields"`
	DestinationImportVerified     bool              `json:"destination_import_verified"`
	Caveats                       []string          `json:"caveats"`
}

// ComparisonGroup preserves all possible identities for equal projections.
// Counts establish multiplicity; duplicate groups do not establish pairings.
type ComparisonGroup struct {
	Code               string `json:"code"`
	SourceRecords      []int  `json:"source_records"`
	DestinationRecords []int  `json:"destination_records"`
	MatchedRecords     int    `json:"matched_records"`
	MissingRecords     int    `json:"missing_records"`
	UnexpectedRecords  int    `json:"unexpected_records"`
}

type ComparisonField struct {
	Record int    `json:"record"`
	Field  int    `json:"field"`
	Code   string `json:"code"`
}

// Compare matches exact meaningful projections as a multiset. Private canonical
// keys stay in memory and never appear in the returned report. Unknown destination
// fields remain meaningful, so their addition can prevent a match.
func (d *Document) Compare(target Format, selection []int, destination *Document) (Comparison, error) {
	if d == nil || destination == nil || destination.format != target || destination.provider == nil {
		return Comparison{}, &SafeError{Code: "unsupported_route"}
	}
	switch target {
	case BitwardenJSON, OnePassword1PUX, ProtonPassZIP:
	default:
		return Comparison{}, &SafeError{Code: "unsupported_route"}
	}
	selected, err := d.Select(Selection{Items: selection})
	if err != nil {
		return Comparison{}, err
	}
	mapped, err := d.mappedItems(target, selectedOrNil(selected))
	if err != nil {
		return Comparison{}, err
	}
	if len(mapped) != len(selected) {
		return Comparison{}, &SafeError{Code: "output_validation"}
	}
	report := Comparison{
		Source: d.format, Target: target, State: "destination_compared",
		ExpectedRecords: len(selected), DestinationRecords: len(destination.provider.records),
		Groups:                        make([]ComparisonGroup, 0),
		SourceUnobservableFields:      make([]ComparisonField, 0),
		DestinationUnobservableFields: make([]ComparisonField, 0),
		SourceMetadataFields:          d.inventory.MetadataFields,
		DestinationMetadataFields:     destination.inventory.MetadataFields,
		Caveats:                       []string{"supplied_destination_export_only", "comparison_matches_meaningful_projection_only", "source_export_may_omit_account_data", "destination_export_may_omit_account_data", "destination_import_not_verified", "provider_metadata_unobservable", "provider_canonicalization_may_prevent_matches", "passkey_functionality_not_verified"},
	}
	indexes := make(map[string]int, len(selected))
	for i, item := range mapped {
		if item.value == nil {
			return Comparison{}, &SafeError{Code: "unsupported_route"}
		}
		key, err := comparisonKey(target, item.value)
		if err != nil {
			return Comparison{}, err
		}
		index, present := indexes[key]
		if !present {
			index = len(report.Groups)
			indexes[key] = index
			report.Groups = append(report.Groups, ComparisonGroup{SourceRecords: []int{}, DestinationRecords: []int{}})
		}
		report.Groups[index].SourceRecords = append(report.Groups[index].SourceRecords, selected[i])
		report.SourceUnobservableFields = append(report.SourceUnobservableFields, d.comparisonUnobservable(target, selected[i], item)...)
	}
	for i, record := range destination.provider.records {
		key, err := comparisonKey(target, record.value)
		if err != nil {
			return Comparison{}, err
		}
		index, present := indexes[key]
		if !present {
			index = len(report.Groups)
			indexes[key] = index
			report.Groups = append(report.Groups, ComparisonGroup{SourceRecords: []int{}, DestinationRecords: []int{}})
		}
		report.Groups[index].DestinationRecords = append(report.Groups[index].DestinationRecords, i+1)
		for field, value := range record.fields {
			if comparisonExcluded(target, value.path) {
				report.DestinationUnobservableFields = append(report.DestinationUnobservableFields, ComparisonField{i + 1, field + 1, "provider_metadata_unobservable"})
			}
		}
	}
	for i := range report.Groups {
		group := &report.Groups[i]
		expected, actual := len(group.SourceRecords), len(group.DestinationRecords)
		group.MatchedRecords = min(expected, actual)
		group.MissingRecords = expected - group.MatchedRecords
		group.UnexpectedRecords = actual - group.MatchedRecords
		switch {
		case expected == 0:
			group.Code = "unexpected_destination"
		case actual == 0:
			group.Code = "missing_destination"
		case expected > 1 || actual > 1:
			group.Code = "ambiguous_match"
		default:
			group.Code = "matched"
		}
		report.MatchedRecords += group.MatchedRecords
		report.MissingRecords += group.MissingRecords
		report.UnexpectedRecords += group.UnexpectedRecords
	}
	if len(report.SourceUnobservableFields) != 0 {
		report.Caveats = append(report.Caveats, "source_fields_unobservable")
	}
	for _, ordinal := range selected {
		if d.provider != nil && d.provider.records[ordinal-1].kind == "ssh_key" {
			report.Caveats = append(report.Caveats, "ssh_private_key_representation_compared_semantically")
			break
		}
	}
	return report, nil
}

func (d *Document) comparisonUnobservable(target Format, ordinal int, item mappedRecord) []ComparisonField {
	result := make([]ComparisonField, 0)
	var fields []sourceField
	if IsBrowserFormat(d.format) {
		fields = make([]sourceField, len(d.chromeHeaders))
		for i := range fields {
			fields[i].path = "/" + strconv.Itoa(i)
		}
	} else {
		fields = d.provider.records[ordinal-1].fields
	}
	for i, field := range fields {
		mapping, present := item.mappings[field.path]
		code := ""
		switch {
		case !present || (mapping.disposition != "native" && mapping.disposition != "relocated" && mapping.disposition != "transformed"):
			code = "source_field_unobservable"
		case comparisonExcludedTarget(target, mapping.target):
			code = "provider_metadata_unobservable"
		case strings.Contains(mapping.target, "sshKey") && strings.HasSuffix(mapping.target, "privateKey"):
			code = "ssh_original_representation_unobservable"
		}
		if code != "" {
			result = append(result, ComparisonField{ordinal, i + 1, code})
		}
	}
	return result
}

func comparisonExcludedTarget(target Format, path string) bool {
	if strings.HasPrefix(path, "/") {
		return comparisonExcluded(target, path)
	}
	return comparisonExcluded(target, "/"+strings.ReplaceAll(path, ".", "/"))
}

// IDs and mutable provider bookkeeping cannot establish source preservation.
// Explicit states, favorites, deletion dates, credential histories, arbitrary
// custom fields, and unknown payloads remain in the meaningful projection.
func comparisonExcluded(target Format, path string) bool {
	var paths []string
	switch target {
	case BitwardenJSON:
		paths = []string{"/id", "/folderId", "/organizationId", "/collectionIds", "/creationDate", "/revisionDate"}
	case OnePassword1PUX:
		paths = []string{"/uuid", "/createdAt", "/updatedAt", "/overview/subtitle", "/overview/ainfo"}
	case ProtonPassZIP:
		paths = []string{"/itemId", "/shareId", "/folderId", "/createTime", "/modifyTime", "/contentFormatVersion", "/shareCount", "/data/metadata/itemUuid"}
	}
	for _, excluded := range paths {
		if path == excluded || strings.HasPrefix(path, excluded+"/") {
			return true
		}
	}
	return false
}

func comparisonKey(target Format, item map[string]any) (string, error) {
	if item == nil {
		return "", &SafeError{Code: "output_validation"}
	}
	projection, _ := comparisonProjection(target, item, "")
	if target == BitwardenJSON && isIntegerType(item["type"], "5") {
		if root, ok := projection.(map[string]any); ok {
			if key, ok := root["sshKey"].(map[string]any); ok {
				canonicalSSHValue(key, "privateKey")
			}
		}
	}
	if target == OnePassword1PUX && item["categoryUuid"] == "114" {
		if root, ok := projection.(map[string]any); ok {
			details, _ := root["details"].(map[string]any)
			sections, _ := details["sections"].([]any)
			for _, rawSection := range sections {
				section, _ := rawSection.(map[string]any)
				fields, _ := section["fields"].([]any)
				for _, rawField := range fields {
					field, _ := rawField.(map[string]any)
					value, _ := field["value"].(map[string]any)
					key, _ := value["sshKey"].(map[string]any)
					canonicalSSHValue(key, "privateKey")
					metadata, _ := key["metadata"].(map[string]any)
					canonicalSSHValue(metadata, "privateKey")
				}
			}
		}
	}
	key, err := json.Marshal(projection)
	if err != nil {
		return "", &SafeError{Code: "output_validation"}
	}
	return string(key), nil
}

func canonicalSSHValue(value map[string]any, key string) {
	if private, ok := value[key].(string); ok {
		if canonical, err := onePasswordSSHCanonical(private); err == nil {
			value[key] = canonical
		}
	}
}

func isIntegerType(value any, want string) bool {
	switch v := value.(type) {
	case json.Number:
		return v.String() == want
	case int:
		return strconv.Itoa(v) == want
	}
	return false
}

func comparisonProjection(target Format, value any, path string) (any, bool) {
	if comparisonExcluded(target, path) {
		return nil, false
	}
	switch value := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(value))
		for key, child := range value {
			escaped := strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
			if projected, keep := comparisonProjection(target, child, path+"/"+escaped); keep {
				result[key] = projected
			}
		}
		// A parent containing only excluded metadata is itself unobservable.
		// An originally empty container remains present and distinguishable.
		return result, len(value) == 0 || len(result) != 0 || path == ""
	case []any:
		// Exclusion paths refer only to entire fixed fields, never array slots.
		// Preserve array order and every element, including empty containers.
		result := make([]any, len(value))
		for i, child := range value {
			result[i], _ = comparisonProjection(target, child, path)
		}
		return result, true
	default:
		return value, true
	}
}
