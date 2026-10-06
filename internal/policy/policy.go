package policy

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
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
	gcloudPath, err := exec.LookPath("gcloud")
	if err != nil {
		return err
	}

	args := []string{
		"compute",
		"os-config",
		"os-policy-assignments",
		"create",
		fmt.Sprintf("crowdstrike-sensor-deploy-%s", a.Zone),
		fmt.Sprintf("--file=%s", a.PolicyTemplatePath),
		fmt.Sprintf("--location=%s", a.Zone),
	}

	if a.SkipWait {
		args = append(args, "--async")
	}

	bufErr := new(bytes.Buffer)

	cmd := exec.CommandContext(ctx, gcloudPath, args...)
	cmd.Stderr = bufErr
	err = cmd.Run()

	a.lock.Lock()
	defer a.lock.Unlock()
	a.done = true

	if ctx.Err() == context.Canceled {
		a.failed = true
	}

	if err != nil {
		if strings.Contains(bufErr.String(), "ALREADY_EXISTS: Requested entity already exists") {
			return nil
		}

		a.failed = true
		return errors.New(bufErr.String())
	}

	return nil
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
