package migration

import (
	"reflect"
	"testing"
)

func selectionFixture() *Document {
	return &Document{format: OnePassword1PUX, provider: &providerData{
		vaultCount: 3, folderCount: 2,
		records: []providerRecord{
			{kind: "login", vault: 1, folder: 1},
			{kind: "secure_note", vault: 1, folder: 2},
			{kind: "login", vault: 2, folder: 1},
			{kind: "unknown", vault: 2},
		},
	}}
}

func TestSelectionIntersectsAndReturnsSourceOrdinals(t *testing.T) {
	d := selectionFixture()
	for _, tc := range []struct {
		selection Selection
		want      []int
	}{
		{Selection{}, []int{1, 2, 3, 4}},
		{Selection{Items: []int{4, 1}}, []int{1, 4}},
		{Selection{Vaults: []int{2}}, []int{3, 4}},
		{Selection{Folders: []int{1}}, []int{1, 3}},
		{Selection{Kinds: []string{"login"}}, []int{1, 3}},
		{Selection{Items: []int{4, 3, 1}, Vaults: []int{2, 1}, Folders: []int{1}, Kinds: []string{"login"}}, []int{1, 3}},
	} {
		got, err := d.Select(tc.selection)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatal("selection changed source ordering or intersection")
		}
	}
}

func TestSelectionRejectsInvalidAndEmptyCriteria(t *testing.T) {
	d := selectionFixture()
	for _, s := range []Selection{
		{Items: []int{}}, {Items: []int{0}}, {Items: []int{-1}}, {Items: []int{5}}, {Items: []int{1, 1}},
		{Vaults: []int{}}, {Vaults: []int{0}}, {Vaults: []int{4}}, {Vaults: []int{1, 1}},
		{Folders: []int{}}, {Folders: []int{0}}, {Folders: []int{3}}, {Folders: []int{1, 1}},
		{Kinds: []string{}}, {Kinds: []string{""}}, {Kinds: []string{"raw-synthetic-label"}}, {Kinds: []string{"login", "login"}},
		{Items: []int{2}, Kinds: []string{"login"}}, {Vaults: []int{3}},
	} {
		_, err := d.Select(s)
		requireErrorCode(t, err, "invalid_selection")
	}
	var absent *Document
	_, err := absent.Select(Selection{})
	requireErrorCode(t, err, "invalid_selection")
}

func TestChromeSelectionHasLoginKindAndNoContainers(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password\na,b,c,d\ne,f,g,h\n"), ChromeCSV)
	got, err := d.Select(Selection{Kinds: []string{"login"}, Items: []int{2, 1}})
	if err != nil || !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatal("Chrome login selection changed")
	}
	for _, s := range []Selection{{Vaults: []int{1}}, {Folders: []int{1}}, {Kinds: []string{"secure_note"}}} {
		_, err := d.Select(s)
		requireErrorCode(t, err, "invalid_selection")
	}
}

func TestSelectionOwnsReturnedSliceAndAllowsEmptyWholeExport(t *testing.T) {
	d := selectionFixture()
	input := []int{3, 1}
	got, err := d.Select(Selection{Items: input})
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 4
	got[0] = 4
	again, err := d.Select(Selection{})
	if err != nil || !reflect.DeepEqual(again, []int{1, 2, 3, 4}) {
		t.Fatal("selection mutated document")
	}
	empty := &Document{format: OnePassword1PUX, provider: &providerData{}}
	got, err = empty.Select(Selection{})
	if err != nil || got == nil || len(got) != 0 {
		t.Fatal("empty whole export rejected")
	}
}
