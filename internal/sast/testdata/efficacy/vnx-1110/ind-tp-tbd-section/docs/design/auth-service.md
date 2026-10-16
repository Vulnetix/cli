# Auth service design

## Goals

Issue short-lived tokens for internal callers and keep key material in the HSM.

## Threat model

~>TBD

## Data flow

Requests enter through the gateway, which validates the client certificate
before forwarding to the token issuer.
