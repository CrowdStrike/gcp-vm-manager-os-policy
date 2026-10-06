package policy

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseLabelSets(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   []LabelSet
	}{
		{"none", nil, nil},
		{"single label", []string{"crowdstrike-falcon-install:true"},
			[]LabelSet{{Labels: map[string]string{"crowdstrike-falcon-install": "true"}}}},
		{"several labels in one set", []string{"Label:Value, Env:Prod"},
			[]LabelSet{{Labels: map[string]string{"Label": "Value", "Env": "Prod"}}}},
		{"label without value", []string{"team"},
			[]LabelSet{{Labels: map[string]string{"team": ""}}}},
		{"several sets", []string{"env:prod", "env:dev"},
			[]LabelSet{{Labels: map[string]string{"env": "prod"}}, {Labels: map[string]string{"env": "dev"}}}},
		{"empty value ignored", []string{""}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseLabelSets(tt.values); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseLabelSets(%q) = %#v, want %#v", tt.values, got, tt.want)
			}
		})
	}
}

func TestGeneratePolicyInstanceFilter(t *testing.T) {
	tests := []struct {
		name      string
		inclusion []string
		exclusion []string
		want      map[string]any
	}{
		{"no labels targets all VMs", nil, nil, map[string]any{"all": true}},
		{"inclusion labels", []string{"crowdstrike-falcon-install:true"}, nil,
			map[string]any{"inclusionLabels": []any{map[string]any{"labels": map[string]any{"crowdstrike-falcon-install": "true"}}}}},
		{"inclusion and exclusion labels", []string{"falcon:true"}, []string{"env:prod"},
			map[string]any{
				"inclusionLabels": []any{map[string]any{"labels": map[string]any{"falcon": "true"}}},
				"exclusionLabels": []any{map[string]any{"labels": map[string]any{"env": "prod"}}},
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPolicy("cid", "", "", nil, tt.inclusion, tt.exclusion)
			var buf bytes.Buffer
			if err := p.GeneratePolicy(&buf); err != nil {
				t.Fatalf("GeneratePolicy: %v", err)
			}
			var rendered map[string]any
			if err := json.Unmarshal(buf.Bytes(), &rendered); err != nil {
				t.Fatalf("rendered policy is not valid JSON: %v", err)
			}
			if got := rendered["instanceFilter"]; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("instanceFilter = %#v, want %#v", got, tt.want)
			}
		})
	}
}
