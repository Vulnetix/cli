# 7. Use SQS for the job queue

## Context

The cron-based poller cannot keep up with the import volume.

## Decision

Jobs are published to an SQS queue and consumed by the worker pool.

## Security impact

~><!-- TODO: describe IAM scoping for the worker role -->

## Status

Accepted
