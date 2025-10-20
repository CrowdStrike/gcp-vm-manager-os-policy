package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/crowdstrike/gcp-os-policy/internal/policy"
)

type PolicyModel struct {
	width     int
	completed int
	spinner   spinner.Model

	Assignments []*policy.Assignment
}

func NewPolicyModel() PolicyModel {
	s := spinner.New()
	s.Spinner = spinner.MiniDot

	return PolicyModel{
		spinner: s,
	}
}

func (m PolicyModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, tick())
}

func (m PolicyModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tickMsg:
		var completed int

		for _, assignment := range m.Assignments {
			if assignment.Done() {
				completed += 1
			}
		}

		m.completed = completed

		if m.completed != len(m.Assignments) {
			return m, tick()
		}

		return m, tea.Quit
	}

	return m, nil
}

func (m PolicyModel) View() string {
	s := strings.Builder{}

	for _, a := range m.Assignments {
		var line string
		if a.Done() {
			icon := Green(SuccessIcon)
			if a.Failed() {
				icon = Red(FailIcon)
			}
			line = fmt.Sprintf("  %s %s\n", icon, a.Zone)
		} else {
			line = fmt.Sprintf("  %s %s\n", m.spinner.View(), a.Zone)
		}

		s.WriteString(line)
	}

	// if m.completed != len(m.Assignments) && !m.Assignments[0].SkipWait {
	prefix := Yellow(WarningIcon)
	notice := fmt.Sprintf(
		"\n\n%s This may take a while depending on your rollout settings and number of instances. You can use --skip-wait to create the assignments without waiting for the rollout to complete.",
		prefix,
	)
	s.WriteString(DefaultStyle.Width(m.width).PaddingLeft(2).Render(notice))
	// }

	s.WriteString("\n\n")
	return s.String()
}
