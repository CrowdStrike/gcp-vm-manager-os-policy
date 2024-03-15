package github

import (
	"fmt"
	"net/url"
)

const repoUrl = "https://github.com/crowdstrike/gcp-os-policy"

func IssueUrl(body string) (string, error) {
	issueUrl := fmt.Sprintf("%s/issues/new", repoUrl)
	u, err := url.Parse(issueUrl)
	q := u.Query()

	if err != nil {
		return "", err
	}

	q.Set("body", body)
	u.RawQuery = q.Encode()

	return u.String(), nil
}
