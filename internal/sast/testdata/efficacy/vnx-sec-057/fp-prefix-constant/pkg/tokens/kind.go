package tokens

import "strings"

const serviceAccountPrefix = "glsa_"

func IsCloud(tok string) bool { return strings.HasPrefix(tok, "glc_") }
