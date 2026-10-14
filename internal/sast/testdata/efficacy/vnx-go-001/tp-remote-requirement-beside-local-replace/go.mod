module github.com/acme/monorepo/services/worker

go 1.22

~>require (
	github.com/acme/monorepo/libs/queue v0.0.0
	github.com/redis/go-redis/v9 v9.5.1
	github.com/old/fork v1.0.0
)

replace github.com/acme/monorepo/libs/queue => ../../libs/queue

// A module replaced by another remote module is still downloaded and must
// still be checksummed.
replace github.com/old/fork => github.com/new/fork v1.2.0
