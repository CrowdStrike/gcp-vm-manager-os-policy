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

	s.WriteString("\n")
	return s.String()
}
