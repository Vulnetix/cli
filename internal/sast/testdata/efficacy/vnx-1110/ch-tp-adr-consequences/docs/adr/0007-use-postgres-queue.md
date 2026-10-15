# 7. Use Postgres as the job queue

## Status

Accepted

## Context

We run one database already and want to avoid operating a broker.

## Decision

Jobs are rows claimed with SELECT ... FOR UPDATE SKIP LOCKED.

## Consequences

~>To be determined.
