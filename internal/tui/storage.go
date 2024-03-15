package tui

import (
	"math"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/crowdstrike/gcp-os-policy/internal/sensor"
	"github.com/muesli/termenv"
)

type StorageSyncModel struct {
	width     int
	Sensors   []*sensor.Sensor
	total     int64
	written   int64
	completed int
}

var progressBarColor = "#404040"

func (m StorageSyncModel) Init() tea.Cmd {
	// windows terminal always returns true
	// https://github.com/muesli/termenv/issues/46
	if termenv.HasDarkBackground() {
		progressBarColor = "#F2F3F2"
	}

	return tick()
}

func (m StorageSyncModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case tickMsg:
		var total int64
		var written int64
		var completed int
		for _, s := range m.Sensors {
			if s.ProgressWriter == nil {
				continue
			}

			total += s.ProgressWriter.Total()
			written += s.ProgressWriter.N()

			if s.ProgressWriter.Done() {
				completed += 1
			}

			m.total = total
			m.written = written
			m.completed = completed
		}

		if m.completed != len(m.Sensors) {
			return m, tick()
		}

		return m, tea.Quit
	}

	return m, nil
}

func (m StorageSyncModel) View() string {
	s := strings.Builder{}
	s.WriteString("\n")

	prefix := "Ensuring binaries exist in bucket... "
	s.WriteString(prefix)

	percent := float64(m.written) / float64(m.total)

	if math.IsNaN(percent) || math.IsInf(percent, 0) {
		percent = 0
	}

	if m.completed == len(m.Sensors) {
		percent = 100
	}

	s.WriteString(
		progress.New(progress.WithWidth((m.width-len(prefix))/2), progress.WithSolidFill(progressBarColor)).
			ViewAs(percent),
	)

	s.WriteString("\n")

	return s.String()
}

type tickMsg time.Time

// tick sends a basic tick command to the tea program
func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}
