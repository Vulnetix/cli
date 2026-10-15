---
title: Architecture
weight: 20
# draft: true
# aliases: [/arch/]
---

# Architecture

The ingest service receives uploads and hands them to the worker pool over a
durable queue. Workers write results to Postgres and emit events to the bus.

## Storage

All state lives in a single Postgres cluster with point-in-time recovery.
