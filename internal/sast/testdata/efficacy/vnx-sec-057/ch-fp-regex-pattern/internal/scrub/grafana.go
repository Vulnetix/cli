package scrub

import "regexp"

var grafanaToken = regexp.MustCompile(`glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`)
var grafanaCloud = regexp.MustCompile(`glc_eyJ[A-Za-z0-9+/=]{20,}`)
