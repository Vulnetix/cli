package deploy

import "os"

// Tokens look like glsa_<32 chars>_<8 hex>; never commit one.
func Token() string {
	return os.Getenv("GRAFANA_SA_TOKEN")
}
