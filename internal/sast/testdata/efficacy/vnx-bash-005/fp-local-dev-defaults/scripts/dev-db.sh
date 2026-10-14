#!/bin/bash
export PGPASSWORD=postgres
docker run -d -e POSTGRES_PASSWORD=devlocal -p 5432:5432 postgres:16
DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:5432/app"
REDIS_URL="redis://default:localdev@localhost:6379/0"
