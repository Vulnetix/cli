package store

import "go.mongodb.org/mongo-driver/mongo/options"

~>var clientOpts = options.Client().ApplyURI("mongodb://ingest:@@sample:[A-Za-z0-9]{20}@@@mongo.acme.internal:27017")
