package model

import "strings"

// PersonalEmailDomains lists email domains considered personal providers.
// Used by both the collector and analyzer packages for maintainer risk assessment.
var PersonalEmailDomains = map[string]bool{
	"gmail.com":      true,
	"protonmail.com": true,
	"proton.me":      true,
	"outlook.com":    true,
	"hotmail.com":    true,
	"yahoo.com":      true,
	"live.com":       true,
	"icloud.com":     true,
	"me.com":         true,
}

// IsPersonalEmail reports whether the given email address belongs to a
// personal provider such as Gmail, ProtonMail, Outlook, Yahoo, or iCloud.
func IsPersonalEmail(email string) bool {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return false
	}
	return PersonalEmailDomains[strings.ToLower(parts[1])]
}
