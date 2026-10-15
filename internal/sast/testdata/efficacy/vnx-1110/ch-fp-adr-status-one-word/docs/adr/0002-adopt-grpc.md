# 2. Adopt gRPC between services

## Status

Superseded by ADR 9

## Context

Services spoke JSON over HTTP with hand-written clients.

## Decision

Internal calls use gRPC with generated stubs.

## Consequences

Schemas are versioned in one repository; TODO lists in the services were replaced by tracked issues.
