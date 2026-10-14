package oauth

import "strings"

const googleSecretPrefix = "GOCSPX-"

func looksLikeGoogleSecret(s string) bool { return strings.HasPrefix(s, googleSecretPrefix) && len(s) == 35 }
