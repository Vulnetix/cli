module github.com/acme/exporter

go 1.21

~>require github.com/prometheus/client_golang v1.19.0

// carry the label-cardinality patch until upstream merges it
replace github.com/prometheus/client_golang => github.com/acme-forks/client_golang v1.19.1-acme.1
