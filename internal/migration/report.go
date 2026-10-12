package migration

type Inventory struct {
	Format             Format         `json:"format"`
	Records            int            `json:"records"`
	Fields             int            `json:"fields"`
	MetadataFields     int            `json:"metadata_fields"`
	Kinds              map[string]int `json:"kinds"`
	DuplicateGroups    [][]int        `json:"duplicate_groups"`
	DuplicateDetection string         `json:"duplicate_detection"`
	Caveats            []string       `json:"caveats"`
}

type Plan struct {
	Source                    Format             `json:"source"`
	Target                    Format             `json:"target"`
	State                     string             `json:"state"`
	TotalRecords              int                `json:"total_records"`
	SelectedRecords           int                `json:"selected_records"`
	ExcludedRecords           int                `json:"excluded_records"`
	Fields                    []FieldDisposition `json:"fields"`
	Metadata                  []FieldDisposition `json:"metadata,omitempty"`
	DuplicateGroups           [][]int            `json:"duplicate_groups"`
	OutputEmitted             bool               `json:"output_emitted"`
	DestinationImportVerified bool               `json:"destination_import_verified"`
	Caveats                   []string           `json:"caveats"`
}

type FieldDisposition struct {
	Record      int    `json:"record"`
	Field       int    `json:"field"`
	Disposition string `json:"disposition"`
	TargetField string `json:"target_field"`
	Concealed   bool   `json:"concealed"`
}

func newInventory(format Format) Inventory {
	return Inventory{
		Format:          format,
		Kinds:           map[string]int{"login": 0, "secure_note": 0, "card": 0, "identity": 0, "ssh_key": 0, "unknown": 0},
		DuplicateGroups: make([][]int, 0),
		Caveats:         []string{"source_export_may_omit_account_data"},
	}
}

// Inspect returns owned report collections so callers cannot mutate document state.
func (d *Document) Inspect() Inventory {
	if d == nil {
		return newInventory("")
	}
	report := d.inventory
	report.Kinds = make(map[string]int, len(d.inventory.Kinds))
	for kind, count := range d.inventory.Kinds {
		report.Kinds[kind] = count
	}
	report.DuplicateGroups = cloneGroups(d.inventory.DuplicateGroups)
	report.Caveats = append([]string{}, d.inventory.Caveats...)
	return report
}

func cloneGroups(groups [][]int) [][]int {
	cloned := make([][]int, len(groups))
	for i, group := range groups {
		cloned[i] = append([]int{}, group...)
	}
	return cloned
}
