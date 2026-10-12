package migration

import "strings"

func providerProfile(source, target Format) string {
	if IsBrowserFormat(source) && (target == BitwardenJSON || target == OnePassword1PUX || target == ProtonPassZIP) {
		return string(source) + "-to-" + string(target) + "-v1"
	}
	switch {
	case source == BitwardenJSON && target == OnePassword1PUX:
		return "bitwarden-to-onepassword-1pux-v1"
	case source == OnePassword1PUX && target == BitwardenJSON:
		return "onepassword-1pux-to-bitwarden-json-v1"
	case source == BitwardenJSON && target == ProtonPassZIP:
		return "bitwarden-to-proton-pass-zip-v1"
	case source == ProtonPassZIP && target == BitwardenJSON:
		return "proton-pass-zip-to-bitwarden-json-v1"
	case source == OnePassword1PUX && target == ProtonPassZIP:
		return "onepassword-1pux-to-proton-pass-zip-v1"
	case source == ProtonPassZIP && target == OnePassword1PUX:
		return "proton-pass-zip-to-onepassword-1pux-v1"
	}
	return "unsupported"
}

// Apply the same researched target importer hazards to every Bitwarden route.
// Conditions examine private values; only fixed codes/counts leave the engine.
func bitwardenTargetIssues(mapped []mappedRecord) []Issue {
	conditions := []struct {
		id, code string
		read     func(map[string]any) (string, bool)
		blank    bool
	}{
		{"provider-blank-name", "import_name_placeholder", func(m map[string]any) (string, bool) { v, ok := m["name"].(string); return v, ok }, true},
		{"provider-blank-notes", "import_notes_null", func(m map[string]any) (string, bool) { v, ok := m["notes"].(string); return v, ok }, true},
		{"provider-empty-username", "import_username_absent", func(m map[string]any) (string, bool) {
			l, _ := m["login"].(map[string]any)
			v, ok := l["username"].(string)
			return v, ok
		}, false},
		{"provider-empty-password", "import_password_absent", func(m map[string]any) (string, bool) {
			l, _ := m["login"].(map[string]any)
			v, ok := l["password"].(string)
			return v, ok
		}, false},
	}
	issues := []Issue{}
	for _, condition := range conditions {
		affected := 0
		for _, item := range mapped {
			v, ok := condition.read(item.value)
			if ok && (v == "" || condition.blank && ecmaBlank(v)) {
				affected++
			}
		}
		if affected > 0 {
			issues = append(issues, Issue{ID: condition.id, Code: condition.code, Records: affected})
		}
	}
	uriAffected := 0
	for _, item := range mapped {
		login, _ := item.value["login"].(map[string]any)
		uris, _ := login["uris"].([]any)
		for _, v := range uris {
			uri, _ := v.(map[string]any)
			if value, ok := uri["uri"].(string); ok && value == "" {
				uriAffected++
				break
			}
		}
	}
	if uriAffected > 0 {
		issues = append(issues, Issue{ID: "provider-empty-url", Code: "import_uri_removed", Records: uriAffected})
	}
	if len(mapped) > 0 {
		rejected := true
		for _, index := range []int{0, len(mapped) / 2, len(mapped) - 1} {
			item := mapped[index].value
			name, _ := item["name"].(string)
			login, _ := item["login"].(map[string]any)
			password, _ := login["password"].(string)
			if (name != "--" && !ecmaBlank(name)) || !ecmaBlank(password) {
				rejected = false
				break
			}
		}
		if rejected {
			issues = append(issues, Issue{ID: "provider-import-rejection", Code: "import_sample_rejected", Records: len(mapped)})
		}
	}
	if len(mapped) > 7000 {
		issues = append(issues, Issue{ID: "provider-large-export", Code: "import_item_limit", Records: len(mapped)})
	}
	return issues
}

// Kept separate from arbitrary source strings so downstream code can normalize
// only fixed schema paths when matching issue locations.
func fixedTargetPointer(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + strings.NewReplacer(".", "/", "[", "/", "]", "").Replace(path)
}

func providerReviewIssues(plan Plan) []Issue {
	issues := []Issue{{ID: "experimental-import", Code: "experimental_import", Records: plan.SelectedRecords}}
	for _, disposition := range []string{"unsupported", "omitted", "transformed", "relocated"} {
		issue := Issue{ID: "fields-" + disposition, Code: "fields_" + disposition}
		affected := map[int]bool{}
		for _, field := range plan.Fields {
			if field.Disposition == disposition {
				issue.Locations = append(issue.Locations, FieldOrdinal{field.Record, field.Field})
				affected[field.Record] = true
			}
		}
		issue.Records = len(affected)
		if len(issue.Locations) > 0 {
			issues = append(issues, issue)
		}
	}
	if len(plan.Metadata) > 0 {
		issue := Issue{ID: "metadata-unsupported", Code: "metadata_unsupported"}
		for _, field := range plan.Metadata {
			issue.Locations = append(issue.Locations, FieldOrdinal{0, field.Field})
		}
		issues = append(issues, issue)
	}
	if plan.Source != BitwardenJSON && plan.Target != BitwardenJSON {
		issues = append(issues, Issue{ID: "intermediary-mapping", Code: "intermediary_mapping", Records: plan.SelectedRecords})
	}
	return issues
}
