package migration

import (
	"encoding/json"
	"strconv"
	"time"
)

const providerDuplicateRule = "exact_provider_content_v1"

// providerDuplicateGroups flags conservative candidates without changing any
// record. Native vault/folder relationships and the complete raw item tree
// participate. Only well-typed item identity and creation/modification fields
// are exempt; no key, password, text, array, or unknown payload is normalized.
// Private canonical JSON keys never leave memory. Indexing avoids pairwise
// comparisons; JSON object-key sorting costs O(fields log fields) per object.
func providerDuplicateGroups(format Format, records []providerRecord) ([][]int, error) {
	type key struct {
		vault, folder int
		content       string
	}
	positions := make(map[key]int, len(records))
	groups := make([][]int, 0)
	for i, record := range records {
		if record.value == nil {
			return nil, &SafeError{Code: "invalid_item", Record: i + 1}
		}
		content, err := json.Marshal(providerDuplicateContent(format, record.value))
		if err != nil {
			return nil, &SafeError{Code: "invalid_item", Record: i + 1}
		}
		candidate := key{record.vault, record.folder, string(content)}
		index, present := positions[candidate]
		if !present {
			index = len(groups)
			positions[candidate] = index
			groups = append(groups, nil)
		}
		groups[index] = append(groups[index], i+1)
	}
	duplicates := make([][]int, 0)
	for _, group := range groups {
		if len(group) >= 2 {
			duplicates = append(duplicates, group)
		}
	}
	return duplicates, nil
}

// Copy only maps whose native bookkeeping fields may be removed. All other
// descendants remain exact, read-only source values during JSON serialization.
func providerDuplicateContent(format Format, raw map[string]any) map[string]any {
	content := providerDuplicateCopy(raw)
	var identity string
	var timestamps []string
	switch format {
	case BitwardenJSON:
		identity, timestamps = "id", []string{"creationDate", "revisionDate"}
	case OnePassword1PUX:
		identity, timestamps = "uuid", []string{"createdAt", "updatedAt"}
	case ProtonPassZIP:
		identity, timestamps = "itemId", []string{"createTime", "modifyTime"}
		if data, ok := raw["data"].(map[string]any); ok {
			if metadata, ok := data["metadata"].(map[string]any); ok && providerDuplicateIdentity(metadata["itemUuid"]) {
				dataCopy := providerDuplicateCopy(data)
				metadataCopy := providerDuplicateCopy(metadata)
				delete(metadataCopy, "itemUuid")
				dataCopy["metadata"] = metadataCopy
				content["data"] = dataCopy
			}
		}
	}
	if identity != "" && providerDuplicateIdentity(raw[identity]) {
		delete(content, identity)
	}
	for _, field := range timestamps {
		if providerDuplicateTimestamp(format, raw[field]) {
			delete(content, field)
		}
	}
	return content
}

func providerDuplicateCopy(raw map[string]any) map[string]any {
	copy := make(map[string]any, len(raw))
	for field, value := range raw {
		copy[field] = value
	}
	return copy
}

// Exempt nonempty printable ASCII identity tokens only. Empty, whitespace,
// Unicode, numeric, null, or structured values remain meaningful source data.
func providerDuplicateIdentity(value any) bool {
	identity, ok := value.(string)
	if !ok || identity == "" {
		return false
	}
	for i := range identity {
		if identity[i] < '!' || identity[i] > '~' {
			return false
		}
	}
	return true
}

func providerDuplicateTimestamp(format Format, value any) bool {
	if format == BitwardenJSON {
		text, ok := value.(string)
		if !ok {
			return false
		}
		if !providerDuplicateNativeDate(text) {
			return false
		}
		_, err := time.Parse(time.RFC3339Nano, text)
		return err == nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	seconds, err := strconv.ParseInt(number.String(), 10, 64)
	return err == nil && seconds >= 0 && seconds <= 253402300799 && strconv.FormatInt(seconds, 10) == number.String()
}

// time.Parse accepts single-digit hours, decimal commas, oversized offsets,
// and fractions beyond nanoseconds. Those unfamiliar representations remain
// meaningful; exemption requires the provider's full RFC3339Nano shape.
func providerDuplicateNativeDate(text string) bool {
	if len(text) < 20 || text[:4] == "0000" {
		return false
	}
	for i := 0; i < 19; i++ {
		expected := byte(0)
		switch i {
		case 4, 7:
			expected = '-'
		case 10:
			expected = 'T'
		case 13, 16:
			expected = ':'
		}
		if expected != 0 {
			if text[i] != expected {
				return false
			}
		} else if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	zone := 19
	if text[zone] == '.' {
		zone++
		start := zone
		for zone < len(text) && text[zone] >= '0' && text[zone] <= '9' {
			zone++
		}
		if zone-start < 1 || zone-start > 9 {
			return false
		}
	}
	if len(text)-zone == 1 && text[zone] == 'Z' {
		return true
	}
	if len(text)-zone != 6 || (text[zone] != '+' && text[zone] != '-') || text[zone+3] != ':' {
		return false
	}
	for _, i := range []int{zone + 1, zone + 2, zone + 4, zone + 5} {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	hours := int(text[zone+1]-'0')*10 + int(text[zone+2]-'0')
	minutes := int(text[zone+4]-'0')*10 + int(text[zone+5]-'0')
	return hours <= 23 && minutes <= 59
}

func (d *Document) inventoryProviderDuplicates() error {
	groups, err := providerDuplicateGroups(d.format, d.provider.records)
	if err != nil {
		return err
	}
	d.inventory.DuplicateDetection = providerDuplicateRule
	d.inventory.DuplicateGroups = groups
	d.inventory.Caveats = append(d.inventory.Caveats, "provider_duplicate_candidates_exact_content_only")
	return nil
}

// selectedProviderDuplicateGroups returns owned groups with original source
// ordinals. A selected singleton provides no duplicate candidate to review.
func selectedProviderDuplicateGroups(groups [][]int, selected []int, total int) [][]int {
	selectedRecords := make([]bool, total)
	for _, ordinal := range selected {
		selectedRecords[ordinal-1] = true
	}
	retained := make([][]int, 0)
	for _, group := range groups {
		members := make([]int, 0, len(group))
		for _, ordinal := range group {
			if selectedRecords[ordinal-1] {
				members = append(members, ordinal)
			}
		}
		if len(members) >= 2 {
			retained = append(retained, members)
		}
	}
	return retained
}
