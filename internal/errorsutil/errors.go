package errorsutil

import (
	"fmt"
	"strings"

	"github.com/crowdstrike/gcp-os-policy/internal/github"
	"github.com/crowdstrike/gcp-os-policy/internal/tui"
)

func DefaultError(explanation string, err error) string {
	errMsg := strings.Builder{}
	errMsg.WriteString(
		fmt.Sprintf(
			"%s\n\n %s %s\n",
			explanation,
			tui.Red(tui.FailIcon),
			err.Error(),
		),
	)
	errMsg.WriteString(
		"If you are unsure the cause of the error you can open a github issue for help.",
	)
	errMsg.WriteString(" Below is a link with the error prefilled.\n\n")
	errMsg.WriteString(
		fmt.Sprintf(
			" %s make sure to remove any sensitive information\n\n",
			tui.Yellow(fmt.Sprintf("%s%s %s:", tui.WarningIcon, tui.WarningIcon, "IMPORTANT")),
		),
	)

	issueUrl, _ := github.IssueUrl(fmt.Sprintf("%s\n\n ```\n%s\n```", explanation, err.Error()))
	errMsg.WriteString(issueUrl)
	return errMsg.String()
}
