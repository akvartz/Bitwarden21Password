package migration

import (
	"sort"
	"strconv"
)

// Plan accounts for selected cells without producing an export or asserting import success.
// nil selects all records; a supplied empty selection is invalid.
func (d *Document) Plan(target Format, selection []int) (Plan, error) {
	if d == nil {
		return Plan{}, &SafeError{Code: "unsupported_route"}
	}
	if IsBrowserFormat(d.format) {
		if target == BitwardenJSON {
			return d.planCSV(target, selection)
		}
		if target == OnePassword1PUX || target == ProtonPassZIP {
			return d.planBrowserProvider(target, selection)
		}
	}
	return d.planProvider(target, selection)
}

func (d *Document) planCSV(target Format, selection []int) (Plan, error) {
	if d == nil || !IsBrowserFormat(d.format) || target != BitwardenJSON {
		return Plan{}, &SafeError{Code: "unsupported_route"}
	}
	total := len(d.chromeRows)
	selected := make([]bool, total)
	count := total
	if selection == nil {
		for i := range selected {
			selected[i] = true
		}
	} else {
		if len(selection) == 0 || len(selection) > total {
			return Plan{}, &SafeError{Code: "invalid_selection"}
		}
		count = len(selection)
		for _, record := range selection {
			if record <= 0 || record > total || selected[record-1] {
				return Plan{}, &SafeError{Code: "invalid_selection"}
			}
			selected[record-1] = true
		}
	}
	plan := Plan{
		Source:          d.format,
		Target:          BitwardenJSON,
		State:           "planned",
		TotalRecords:    total,
		SelectedRecords: count,
		ExcludedRecords: total - count,
		Fields:          make([]FieldDisposition, 0, count*len(d.chromeHeaders)),
		DuplicateGroups: make([][]int, 0),
		Caveats:         append([]string{}, d.inventory.Caveats...),
	}
	plan.Caveats = append(plan.Caveats, "planned_only_no_output", "destination_import_not_verified")
	for i := range d.chromeRows {
		if !selected[i] {
			continue
		}
		for column, header := range d.chromeHeaders {
			field := FieldDisposition{Record: i + 1, Field: column + 1, Disposition: "native"}
			switch header {
			case "name":
				field.TargetField = "name"
			case "url":
				field.TargetField = "login.uris[0].uri"
			case "username":
				field.TargetField = "login.username"
			case "password":
				field.TargetField = "login.password"
			case "note":
				field.TargetField = "notes"
			case "totp":
				if d.format == SafariCSV {
					field.TargetField = "login.totp"
				} else {
					field.TargetField = "fields"
					field.Disposition = "relocated"
					field.Concealed = true
				}
			default:
				field.TargetField = "fields"
				field.Disposition = "relocated"
				field.Concealed = true
			}
			plan.Fields = append(plan.Fields, field)
		}
	}
	for _, group := range d.inventory.DuplicateGroups {
		retained := make([]int, 0, len(group))
		for _, record := range group {
			if selected[record-1] {
				retained = append(retained, record)
			}
		}
		if len(retained) >= 2 {
			plan.DuplicateGroups = append(plan.DuplicateGroups, retained)
		}
	}
	return plan, nil
}

func (d *Document) planBrowserProvider(target Format, selection []int) (Plan, error) {
	plan, err := d.planCSV(BitwardenJSON, selection)
	if err != nil {
		return Plan{}, err
	}
	selected, err := d.selectedOrdinals(selection)
	if err != nil {
		return Plan{}, err
	}
	mapped, err := d.mappedItems(target, selectedOrNil(selected))
	if err != nil {
		return Plan{}, err
	}
	plan.Target = target
	for i := range plan.Fields {
		field := &plan.Fields[i]
		recordIndex := sort.SearchInts(selected, field.Record)
		if recordIndex >= len(mapped) {
			return Plan{}, &SafeError{Code: "output_validation"}
		}
		mapping := mapped[recordIndex].mappings["/"+strconv.Itoa(field.Field-1)]
		field.Disposition = mapping.disposition
		field.TargetField = mapping.target
		field.Concealed = mapping.concealed
	}
	plan.Caveats = append(plan.Caveats, "intermediary_mapping")
	return plan, nil
}
