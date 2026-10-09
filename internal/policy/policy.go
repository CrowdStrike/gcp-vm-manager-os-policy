package policy

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"text/template"

	"github.com/crowdstrike/gcp-os-policy/internal/sensor"
)

//go:embed template.json
var policyTemplate string

type osResource struct {
	Bucket     string
	Object     string
	Generation int64
}

// LabelSet is a set of labels that must all match a VM (logical AND).
// A policy with several label sets matches a VM if any set matches (logical OR).
type LabelSet struct {
	Labels map[string]string `json:"labels"`
}

type Policy struct {
	Cid                  string
	LinuxInstallParams   string
	WindowsInstallParams string
	Sles12               osResource
	Sles15               osResource
	Rhel7                osResource
	Rhel8                osResource
	Rhel9                osResource
	Rhel10               osResource
	Oracle7              osResource
	Oracle8              osResource
	Oracle9              osResource
	Oracle10             osResource
	Debian               osResource
	Ubuntu               osResource
	Centos8              osResource
	Centos9              osResource
	Centos10             osResource
	Windows              osResource
	ExclusionLabelSets   []LabelSet
	InclusionLabelSets   []LabelSet
}

func NewPolicy(
	cid string,
	linuxInstallParams string,
	windowsInstallParams string,
	sensors []*sensor.Sensor,
	inclusionLabels []string,
	exclusionLabels []string,
) Policy {
	var policy Policy

	policy.Cid = cid
	policy.LinuxInstallParams = formatLinuxArgs(cid, linuxInstallParams)
	policy.WindowsInstallParams = formatWinArgs(cid, windowsInstallParams)

	osVersionToField := map[string]*osResource{
		"sles12*":   &policy.Sles12,
		"sles15*":   &policy.Sles15,
		"rhel7*":    &policy.Rhel7,
		"rhel8*":    &policy.Rhel8,
		"rhel9*":    &policy.Rhel9,
		"rhel10*":   &policy.Rhel10,
		"ol7*":      &policy.Oracle7,
		"ol8*":      &policy.Oracle8,
		"ol9*":      &policy.Oracle9,
		"ol10*":     &policy.Oracle10,
		"debian":    &policy.Debian,
		"ubuntu":    &policy.Ubuntu,
		"centos8*":  &policy.Centos8,
		"centos9*":  &policy.Centos9,
		"centos10*": &policy.Centos10,
		"windows":   &policy.Windows,
	}

	for _, s := range sensors {
		key := s.OsShortName + s.OsVersion
		if r, ok := osVersionToField[key]; ok {
			fpSplit := strings.Split(s.FullPath, "/")
			*r = osResource{
				Bucket:     strings.Join(fpSplit[:len(fpSplit)-1], "/"),
				Object:     fpSplit[len(fpSplit)-1],
				Generation: s.Generation,
			}
		}
	}

	policy.InclusionLabelSets = parseLabelSets(inclusionLabels)
	policy.ExclusionLabelSets = parseLabelSets(exclusionLabels)

	return policy
}

// parseLabelSets parses label set flags. Each value is one label set of
// comma separated labelName:labelValue pairs, for example "Label:Value,Env:Prod".
// A label without a value (labelName) matches any value.
func parseLabelSets(values []string) []LabelSet {
	var sets []LabelSet
	for _, value := range values {
		set := LabelSet{Labels: map[string]string{}}
		for _, pair := range strings.Split(value, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			name, val, _ := strings.Cut(pair, ":")
			set.Labels[strings.TrimSpace(name)] = strings.TrimSpace(val)
		}
		if len(set.Labels) > 0 {
			sets = append(sets, set)
		}
	}
	return sets
}

// instanceFilter renders the OS Policy Assignment instance filter. Without
// label sets it targets every VM in the zone, which is the previous behavior.
func instanceFilter(p Policy) (string, error) {
	filter := map[string]any{}
	if len(p.InclusionLabelSets) > 0 {
		filter["inclusionLabels"] = p.InclusionLabelSets
	}
	if len(p.ExclusionLabelSets) > 0 {
		filter["exclusionLabels"] = p.ExclusionLabelSets
	}
	if len(filter) == 0 {
		filter["all"] = true
	}
	b, err := json.Marshal(filter)
	return string(b), err
}

func (p Policy) GeneratePolicy(wr io.Writer) error {
	funcMap := template.FuncMap{
		"escapeJSON":     escapeJSON,
		"instanceFilter": instanceFilter,
	}

	t, err := template.New("policy").Funcs(funcMap).Parse(policyTemplate)
	if err != nil {
		return err
	}

	return t.Execute(wr, p)
}

// escapeJSON escapes backslashes for JSON strings only on Windows
func escapeJSON(s string) string {
	if runtime.GOOS == "windows" {
		return strings.ReplaceAll(s, `\`, `\\`)
	}
	return s
}

type Assignment struct {
	Zone               string
	PolicyTemplatePath string
	SkipWait           bool

	lock   sync.RWMutex
	done   bool
	failed bool
}

// Failed returns true if assignment exited with an error
//
// Can be used with Done() to determine if the command completed without error
func (a *Assignment) Failed() bool {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.failed
}

// Done returns rather or not the command has finished
func (a *Assignment) Done() bool {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.done
}

func (a *Assignment) RollOut(ctx context.Context) error {
	gcloudPath, err := lookPath("gcloud")
	if err != nil {
		return err
	}

	name := fmt.Sprintf("crowdstrike-sensor-deploy-%s", a.Zone)
	args := []string{
		"compute",
		"os-config",
		"os-policy-assignments",
		"create",
		name,
		fmt.Sprintf("--file=%s", a.PolicyTemplatePath),
		fmt.Sprintf("--location=%s", a.Zone),
	}

	if a.SkipWait {
		args = append(args, "--async")
	}

	_, stderr, err := runGcloud(ctx, gcloudPath, args...)
	bufErr := bytes.NewBuffer(stderr)

	a.lock.Lock()
	defer a.lock.Unlock()
	a.done = true

	if ctx.Err() == context.Canceled {
		a.failed = true
	}

	if err != nil {
		if strings.Contains(bufErr.String(), "ALREADY_EXISTS: Requested entity already exists") {
			// create doesn't change an existing assignment, so a rerun only succeeds
			// if the assignment already targets the VMs that were asked for.
			if err := a.checkExistingFilter(ctx, gcloudPath, name); err != nil {
				a.failed = true
				return err
			}
			return nil
		}

		a.failed = true
		return errors.New(bufErr.String())
	}

	return nil
}

// lookPath and runGcloud wrap exec so tests can stub gcloud.
var lookPath = exec.LookPath

// runGcloud runs gcloud and returns its stdout and stderr.
var runGcloud = func(ctx context.Context, gcloudPath string, args ...string) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, gcloudPath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// checkExistingFilter returns an error when the zone's existing assignment
// targets different VMs than the policy file, for example when switching an
// all VMs deployment to label scoped targeting.
func (a *Assignment) checkExistingFilter(ctx context.Context, gcloudPath, name string) error {
	requested, err := readInstanceFilter(a.PolicyTemplatePath)
	if err != nil {
		return fmt.Errorf("assignment %s already exists in zone %s, and the policy file's instance filter couldn't be read: %w", name, a.Zone, err)
	}

	stdout, stderr, err := runGcloud(ctx, gcloudPath,
		"compute", "os-config", "os-policy-assignments", "describe", name,
		fmt.Sprintf("--location=%s", a.Zone), "--format=json")
	if err != nil {
		return fmt.Errorf("assignment %s already exists in zone %s, and its instance filter couldn't be checked: %s", name, a.Zone, strings.TrimSpace(string(stderr)))
	}

	var existing struct {
		InstanceFilter instanceFilterSpec `json:"instanceFilter"`
	}
	if err := json.Unmarshal(stdout, &existing); err != nil {
		return fmt.Errorf("assignment %s already exists in zone %s, and its instance filter couldn't be parsed: %w", name, a.Zone, err)
	}

	if existing.InstanceFilter.equal(requested) {
		return nil
	}

	return fmt.Errorf("assignment %s already exists in zone %s and targets %s, not the requested %s. "+
		"Creating it again doesn't change it. To apply the new targeting, run: "+
		"gcloud compute os-config os-policy-assignments update %s --location=%s --file=%s",
		name, a.Zone, existing.InstanceFilter, requested, name, a.Zone, a.PolicyTemplatePath)
}

// instanceFilterSpec is the part of an OS Policy Assignment instance filter
// this tool sets.
type instanceFilterSpec struct {
	All             bool       `json:"all,omitempty"`
	InclusionLabels []LabelSet `json:"inclusionLabels,omitempty"`
	ExclusionLabels []LabelSet `json:"exclusionLabels,omitempty"`
}

func readInstanceFilter(path string) (instanceFilterSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return instanceFilterSpec{}, err
	}
	var file struct {
		InstanceFilter instanceFilterSpec `json:"instanceFilter"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		return instanceFilterSpec{}, err
	}
	return file.InstanceFilter, nil
}

// equal compares filters ignoring the order of label sets, since label sets
// are ORed together.
func (f instanceFilterSpec) equal(other instanceFilterSpec) bool {
	return f.All == other.All &&
		slices.Equal(labelSetKeys(f.InclusionLabels), labelSetKeys(other.InclusionLabels)) &&
		slices.Equal(labelSetKeys(f.ExclusionLabels), labelSetKeys(other.ExclusionLabels))
}

func (f instanceFilterSpec) String() string {
	if f.All {
		return "all VMs"
	}
	var parts []string
	if len(f.InclusionLabels) > 0 {
		parts = append(parts, "VMs with labels "+strings.Join(labelSetKeys(f.InclusionLabels), " or "))
	}
	if len(f.ExclusionLabels) > 0 {
		parts = append(parts, "excluding "+strings.Join(labelSetKeys(f.ExclusionLabels), " or "))
	}
	if len(parts) == 0 {
		return "no VMs"
	}
	return strings.Join(parts, ", ")
}

// labelSetKeys returns each label set as a sorted "name:value,..." string, sorted.
func labelSetKeys(sets []LabelSet) []string {
	keys := make([]string, 0, len(sets))
	for _, set := range sets {
		pairs := make([]string, 0, len(set.Labels))
		for name, value := range set.Labels {
			pairs = append(pairs, name+":"+value)
		}
		sort.Strings(pairs)
		keys = append(keys, strings.Join(pairs, ","))
	}
	sort.Strings(keys)
	return keys
}

func formatWinArgs(cid string, args string) string {
	params := fmt.Sprintf("'/install', '/quiet', '/norestart', 'CID=%s'", cid)

	if len(args) > 0 {
		sArgs := strings.Split(args, " ")
		for i, arg := range sArgs {
			if !strings.HasPrefix(arg, "'") {
				sArgs[i] = "'" + arg
			}

			if !strings.HasSuffix(arg, "'") {
				sArgs[i] = sArgs[i] + "'"
			}
		}

		params = fmt.Sprintf("%s, %s", params, strings.Join(sArgs, ", "))
	}

	return strings.ReplaceAll(params, "\"", "\\\"")
}

func formatLinuxArgs(cid string, args string) string {
	params := fmt.Sprintf("--cid=%s %s", cid, args)
	return strings.ReplaceAll(params, "\"", "\\\"")
}
