module github.com/acme/monorepo/services/api

go 1.22

require (
	github.com/acme/monorepo/libs/auth v0.0.0
	github.com/acme/monorepo/libs/store v0.0.0-00010101000000-000000000000
)

replace (
	github.com/acme/monorepo/libs/auth => ../../libs/auth
	github.com/acme/monorepo/libs/store v0.0.0-00010101000000-000000000000 => ../../libs/store
)
