# Cache design

## Overview

An LRU cache in front of the catalogue service.

## Security considerations

Entries are keyed by tenant so one tenant cannot read another's entries.
