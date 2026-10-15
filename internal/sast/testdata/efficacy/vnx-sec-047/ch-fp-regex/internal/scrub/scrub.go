package scrub

var shopifyToken = regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`)
var prefixes = []string{"shpat_", "shpca_", "shppa_", "shpss_"}
