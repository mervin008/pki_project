package api

import (
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/store"
)

func fields() []*store.MetadataField {
	return []*store.MetadataField{
		{Key: "cost_centre", Label: "Cost centre", FieldType: store.MetadataText},
		{Key: "pci_in_scope", Label: "PCI in scope", FieldType: store.MetadataBoolean, IsRequired: true},
		{
			Key: "tier", Label: "Service tier", FieldType: store.MetadataSelect,
			Options: []store.MetadataOption{{Value: "tier_1", Label: "Tier 1"}, {Value: "tier_2", Label: "Tier 2"}},
		},
		{
			Key: "regions", Label: "Regions", FieldType: store.MetadataMultiSelect,
			Options: []store.MetadataOption{{Value: "emea", Label: "EMEA"}, {Value: "apac", Label: "APAC"}},
		},
		{Key: "old_system", Label: "Legacy system", FieldType: store.MetadataText, IsArchived: true},
	}
}

func TestEachTypeAcceptsItsOwnShape(t *testing.T) {
	cleaned, err := validateMetadata(fields(), map[string]any{
		"cost_centre":  "  CC-4471 ",
		"pci_in_scope": true,
		"tier":         "tier_1",
		"regions":      []any{"emea", "apac"},
	}, true)
	if err != nil {
		t.Fatalf("validateMetadata: %v", err)
	}
	if cleaned["cost_centre"] != "CC-4471" {
		t.Errorf("text should be trimmed, got %q", cleaned["cost_centre"])
	}
	if cleaned["pci_in_scope"] != true {
		t.Errorf("boolean = %v", cleaned["pci_in_scope"])
	}
	if got := cleaned["regions"].([]any); len(got) != 2 {
		t.Errorf("regions = %v", got)
	}
}

// TestAnUnknownKeyIsAnError is the difference between a filter that returns
// nothing and a filter that returns nothing for a reason you can see. A value
// stored under a misspelled key is invisible: it never appears on a form and
// never matches a filter, and nobody finds out until they go looking for it.
func TestAnUnknownKeyIsAnError(t *testing.T) {
	_, err := validateMetadata(fields(), map[string]any{
		"pci_in_scope": true,
		"cost_center":  "CC-4471", // American spelling; the field is cost_centre
	}, true)
	if err == nil {
		t.Fatal("a value under an undefined key was accepted and would have been stored invisibly")
	}
	if !strings.Contains(err.Error(), "cost_center") {
		t.Errorf("the error should name the offending key, got: %v", err)
	}
}

func TestAValueOutsideTheOptionsIsRefused(t *testing.T) {
	_, err := validateMetadata(fields(), map[string]any{
		"pci_in_scope": true,
		"tier":         "tier_3",
	}, true)
	if err == nil {
		t.Fatal("a value that is not one of the field's options was accepted")
	}
	if !strings.Contains(err.Error(), "Service tier") {
		t.Errorf("the error should name the field by its label, got: %v", err)
	}
}

func TestTheWrongTypeIsRefused(t *testing.T) {
	for name, values := range map[string]map[string]any{
		"string for a boolean": {"pci_in_scope": "yes"},
		"string for a list":    {"pci_in_scope": true, "regions": "emea"},
		"number for text":      {"pci_in_scope": true, "cost_centre": 4471},
	} {
		if _, err := validateMetadata(fields(), values, true); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestARequiredFieldIsEnforcedAtIssuanceOnly(t *testing.T) {
	// Requesting a certificate: the organisation gets to insist.
	if _, err := validateMetadata(fields(), map[string]any{"tier": "tier_1"}, true); err == nil {
		t.Fatal("a missing required field was accepted at issuance")
	}

	// Editing an existing one: marking a field required later must not make
	// every certificate in the estate unsaveable. An operator correcting a team
	// name should not be blocked by a field somebody added this morning.
	if _, err := validateMetadata(fields(), map[string]any{"tier": "tier_1"}, false); err != nil {
		t.Fatalf("an edit was blocked by an unrelated required field: %v", err)
	}
}

func TestAnArchivedFieldTakesNoNewValues(t *testing.T) {
	_, err := validateMetadata(fields(), map[string]any{
		"pci_in_scope": true,
		"old_system":   "mainframe",
	}, true)
	if err == nil {
		t.Fatal("an archived field accepted a new value")
	}
}

func TestEmptyAndNullClearRatherThanStore(t *testing.T) {
	cleaned, err := validateMetadata(fields(), map[string]any{
		"pci_in_scope": true,
		"cost_centre":  "   ",
		"tier":         nil,
		"regions":      []any{},
	}, true)
	if err != nil {
		t.Fatalf("validateMetadata: %v", err)
	}
	for _, key := range []string{"cost_centre", "tier", "regions"} {
		if _, present := cleaned[key]; present {
			t.Errorf("%s was stored as an empty value rather than left absent", key)
		}
	}
}

func TestDuplicateChoicesCollapse(t *testing.T) {
	cleaned, err := validateMetadata(fields(), map[string]any{
		"pci_in_scope": true,
		"regions":      []any{"emea", "emea", "apac"},
	}, true)
	if err != nil {
		t.Fatalf("validateMetadata: %v", err)
	}
	if got := cleaned["regions"].([]any); len(got) != 2 {
		t.Errorf("regions = %v, want the duplicate collapsed", got)
	}
}

func TestKeysAreDerivedFromLabels(t *testing.T) {
	cases := map[string]string{
		"Cost centre":      "cost_centre",
		"PCI in scope?":    "pci_in_scope",
		"  Data  Class  ":  "data_class",
		"2FA required":     "f_2fa_required", // a key must start with a letter
		"Owner / approver": "owner_approver",
	}
	for label, want := range cases {
		if got := slugify(label); got != want {
			t.Errorf("slugify(%q) = %q, want %q", label, got, want)
		}
	}
}

// TestAFieldTypeCannotChangeUnderStoredValues guards the one edit that makes
// existing data unreadable rather than merely stale: flipping a SELECT to a
// BOOLEAN leaves every certificate holding a string the field can no longer
// explain.
func TestAFieldTypeCannotChangeUnderStoredValues(t *testing.T) {
	existing := &store.MetadataField{
		ID: "x", Key: "tier", Label: "Service tier", FieldType: store.MetadataSelect,
		Options: []store.MetadataOption{{Value: "tier_1", Label: "Tier 1"}},
	}
	input := &MetadataFieldInput{Label: "Service tier", FieldType: store.MetadataBoolean}
	if _, err := input.normalize(existing); err == nil {
		t.Fatal("a field's type was changed while certificates hold values for it")
	}
}

// TestAnOptionKeepsItsValueWhenRelabelled is why value and label are separate
// columns. Rewording "Tier 1" to "Business Critical" must not reclassify every
// certificate that already holds tier_1.
func TestAnOptionKeepsItsValueWhenRelabelled(t *testing.T) {
	existing := &store.MetadataField{
		ID: "x", Key: "tier", Label: "Service tier", FieldType: store.MetadataSelect,
		Options: []store.MetadataOption{{Value: "tier_1", Label: "Tier 1"}},
	}
	input := &MetadataFieldInput{Label: "Service tier", FieldType: store.MetadataSelect}
	input.Options = append(input.Options, struct {
		Value string `json:"value"`
		Label string `json:"label"`
	}{Value: "tier_1", Label: "Business Critical"})

	field, err := input.normalize(existing)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if field.Options[0].Value != "tier_1" {
		t.Errorf("value = %q, want tier_1 preserved", field.Options[0].Value)
	}
	if field.Options[0].Label != "Business Critical" {
		t.Errorf("label = %q, want the new wording", field.Options[0].Label)
	}
}

func TestASelectFieldNeedsOptions(t *testing.T) {
	input := &MetadataFieldInput{Label: "Service tier", FieldType: store.MetadataSelect}
	if _, err := input.normalize(nil); err == nil {
		t.Fatal("a SELECT field with no options was accepted; it can never be answered")
	}
}
