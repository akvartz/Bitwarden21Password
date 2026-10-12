package migration

// Selection uses one-based source ordinals and fixed item-kind codes. A nil
// criterion selects everything in that dimension; a supplied empty one is invalid.
type Selection struct {
	Items   []int
	Vaults  []int
	Folders []int
	Kinds   []string
}

// Select intersects the supplied criteria and returns owned item ordinals in
// source order. Container labels and provider IDs never leave the document.
func (d *Document) Select(s Selection) ([]int, error) {
	invalid := &SafeError{Code: "invalid_selection"}
	if d == nil {
		return nil, invalid
	}
	total, vaults, folders := len(d.chromeRows), 0, 0
	if !IsBrowserFormat(d.format) {
		if d.provider == nil {
			return nil, invalid
		}
		total = len(d.provider.records)
		vaults, folders = d.provider.vaultCount, d.provider.folderCount
	}
	items, ok := ordinalCriterion(s.Items, total)
	if !ok {
		return nil, invalid
	}
	vaultSet, ok := ordinalCriterion(s.Vaults, vaults)
	if !ok {
		return nil, invalid
	}
	folderSet, ok := ordinalCriterion(s.Folders, folders)
	if !ok {
		return nil, invalid
	}
	var kinds map[string]bool
	if s.Kinds != nil {
		if len(s.Kinds) == 0 {
			return nil, invalid
		}
		kinds = make(map[string]bool, len(s.Kinds))
		for _, kind := range s.Kinds {
			switch kind {
			case "login", "secure_note", "card", "identity", "ssh_key", "unknown":
			default:
				return nil, invalid
			}
			if kinds[kind] {
				return nil, invalid
			}
			kinds[kind] = true
		}
	}
	selected := make([]int, 0, total)
	for i := 0; i < total; i++ {
		if items != nil && !items[i+1] {
			continue
		}
		kind, vault, folder := "login", 0, 0
		if !IsBrowserFormat(d.format) {
			r := d.provider.records[i]
			kind, vault, folder = r.kind, r.vault, r.folder
		}
		if vaultSet != nil && !vaultSet[vault] {
			continue
		}
		if folderSet != nil && !folderSet[folder] {
			continue
		}
		if kinds != nil && !kinds[kind] {
			continue
		}
		selected = append(selected, i+1)
	}
	if len(selected) == 0 && (s.Items != nil || s.Vaults != nil || s.Folders != nil || s.Kinds != nil) {
		return nil, invalid
	}
	return selected, nil
}

func ordinalCriterion(ordinals []int, total int) (map[int]bool, bool) {
	if ordinals == nil {
		return nil, true
	}
	if len(ordinals) == 0 || len(ordinals) > total {
		return nil, false
	}
	set := make(map[int]bool, len(ordinals))
	for _, ordinal := range ordinals {
		if ordinal <= 0 || ordinal > total || set[ordinal] {
			return nil, false
		}
		set[ordinal] = true
	}
	return set, true
}
