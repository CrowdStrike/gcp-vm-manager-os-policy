package tui

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/mgutz/ansi"
)

var (
	Green       = ansi.ColorFunc("green")
	Red         = ansi.ColorFunc("red")
	Yellow      = ansi.ColorFunc("yellow")
	crwdRed     = lipgloss.Color("#EC0000")
	FailIcon    = "X"
	SuccessIcon = "✓"
	WarningIcon = "!"
	ErrorStyle  = lipgloss.NewStyle().Foreground(crwdRed)
)
