package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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

// stubGcloud replaces gcloud for a test. create returns createStderr and
// createErr; describe returns describeOut, or describeErr when set.
type stubGcloud struct {
	createStderr string
	createErr    error
	describeOut  string
	describeErr  error
	calls        [][]string
}

func (s *stubGcloud) install(t *testing.T) {
	t.Helper()
	origLook, origRun := lookPath, runGcloud
	t.Cleanup(func() { lookPath, runGcloud = origLook, origRun })
	lookPath = func(string) (string, error) { return "gcloud", nil }
	runGcloud = func(_ context.Context, _ string, args ...string) ([]byte, []byte, error) {
		s.calls = append(s.calls, args)
		switch args[3] {
		case "create":
			return nil, []byte(s.createStderr), s.createErr
		case "describe":
			if s.describeErr != nil {
				return nil, []byte("describe failed"), s.describeErr
			}
			return []byte(s.describeOut), nil, nil
		}
		t.Fatalf("unexpected gcloud call %v", args)
		return nil, nil, nil
	}
}

func writePolicyFile(t *testing.T, filter string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"osPolicies":[],"instanceFilter":`+filter+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const alreadyExists = "ERROR: (gcloud.compute.os-config.os-policy-assignments.create) ALREADY_EXISTS: Requested entity already exists"

func TestAssignmentRollOut(t *testing.T) {
	labeled := `{"inclusionLabels":[{"labels":{"crowdstrike-falcon-install":"true"}}]}`
	tests := []struct {
		name          string
		requested     string
		skipWait      bool
		stub          stubGcloud
		wantErr       []string
		wantDescribe  bool
		wantAsyncFlag bool
	}{
		{
			name:      "new assignment is created",
			requested: `{"all":true}`,
		},
		{
			name:          "skip wait passes async",
			requested:     `{"all":true}`,
			skipWait:      true,
			wantAsyncFlag: true,
		},
		{
			name:         "rerun with the same all VMs filter succeeds",
			requested:    `{"all":true}`,
			stub:         stubGcloud{createStderr: alreadyExists, createErr: errors.New("exit 1"), describeOut: `{"instanceFilter":{"all":true}}`},
			wantDescribe: true,
		},
		{
			name:         "rerun with the same label filter succeeds",
			requested:    labeled,
			stub:         stubGcloud{createStderr: alreadyExists, createErr: errors.New("exit 1"), describeOut: `{"instanceFilter":` + labeled + `}`},
			wantDescribe: true,
		},
		{
			name:      "label sets in a different order match",
			requested: `{"inclusionLabels":[{"labels":{"env":"prod"}},{"labels":{"a":"1","b":"2"}}]}`,
			stub: stubGcloud{createStderr: alreadyExists, createErr: errors.New("exit 1"),
				describeOut: `{"instanceFilter":{"inclusionLabels":[{"labels":{"b":"2","a":"1"}},{"labels":{"env":"prod"}}]}}`},
			wantDescribe: true,
		},
		{
			name:         "switching an all VMs assignment to labels fails",
			requested:    labeled,
			stub:         stubGcloud{createStderr: alreadyExists, createErr: errors.New("exit 1"), describeOut: `{"instanceFilter":{"all":true}}`},
			wantErr:      []string{"targets all VMs", "crowdstrike-falcon-install:true", "os-policy-assignments update crowdstrike-sensor-deploy-us-central1-a"},
			wantDescribe: true,
		},
		{
			name:         "switching a label assignment to all VMs fails",
			requested:    `{"all":true}`,
			stub:         stubGcloud{createStderr: alreadyExists, createErr: errors.New("exit 1"), describeOut: `{"instanceFilter":` + labeled + `}`},
			wantErr:      []string{"not the requested all VMs"},
			wantDescribe: true,
		},
		{
			name:         "changing exclusion labels fails",
			requested:    `{"all":true,"exclusionLabels":[{"labels":{"env":"prod"}}]}`,
			stub:         stubGcloud{createStderr: alreadyExists, createErr: errors.New("exit 1"), describeOut: `{"instanceFilter":{"all":true}}`},
			wantErr:      []string{"already exists"},
			wantDescribe: true,
		},
		{
			name:         "existing filter that can't be read fails",
			requested:    labeled,
			stub:         stubGcloud{createStderr: alreadyExists, createErr: errors.New("exit 1"), describeErr: errors.New("exit 1")},
			wantErr:      []string{"couldn't be checked", "describe failed"},
			wantDescribe: true,
		},
		{
			name:      "other create errors are returned",
			requested: `{"all":true}`,
			stub:      stubGcloud{createStderr: "PERMISSION_DENIED", createErr: errors.New("exit 1")},
			wantErr:   []string{"PERMISSION_DENIED"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := tt.stub
			stub.install(t)
			a := &Assignment{Zone: "us-central1-a", PolicyTemplatePath: writePolicyFile(t, tt.requested), SkipWait: tt.skipWait}

			err := a.RollOut(context.Background())

			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("RollOut() error = %v, want nil", err)
				}
				if a.Failed() {
					t.Error("Failed() = true, want false")
				}
			} else {
				if err == nil {
					t.Fatal("RollOut() error = nil, want an error")
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("RollOut() error = %q, want it to contain %q", err, want)
					}
				}
				if !a.Failed() {
					t.Error("Failed() = false, want true")
				}
			}
			if !a.Done() {
				t.Error("Done() = false, want true")
			}

			described := len(stub.calls) > 1 && stub.calls[1][3] == "describe"
			if described != tt.wantDescribe {
				t.Errorf("describe called = %v, want %v (calls %v)", described, tt.wantDescribe, stub.calls)
			}
			hasAsync := slices.Contains(stub.calls[0], "--async")
			if hasAsync != tt.wantAsyncFlag {
				t.Errorf("--async = %v, want %v", hasAsync, tt.wantAsyncFlag)
			}
		})
	}
}

func TestReadInstanceFilterFromGeneratedPolicy(t *testing.T) {
	// The check reads the filter back from the rendered policy file, so the
	// rendered template must parse as JSON with the filter that was asked for.
	for _, inclusion := range [][]string{nil, {"crowdstrike-falcon-install:true"}} {
		var buf bytes.Buffer
		if err := NewPolicy("cid", "", "", nil, inclusion, nil).GeneratePolicy(&buf); err != nil {
			t.Fatalf("GeneratePolicy: %v", err)
		}
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readInstanceFilter(path)
		if err != nil {
			t.Fatalf("readInstanceFilter() error = %v", err)
		}
		want := instanceFilterSpec{All: true}
		if inclusion != nil {
			want = instanceFilterSpec{InclusionLabels: parseLabelSets(inclusion)}
		}
		if !got.equal(want) {
			t.Errorf("filter = %v, want %v", got, want)
		}
	}
}
