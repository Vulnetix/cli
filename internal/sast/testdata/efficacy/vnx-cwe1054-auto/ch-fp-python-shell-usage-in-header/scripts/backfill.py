#!/usr/bin/env python3
# Backfill the orders table from the archive bucket.
#
# Usage:
#     export DATABASE_URL=postgres://localhost/shop
#     BATCH=500 python scripts/backfill.py --since 2024-01-01
#     psql "$DATABASE_URL" -c "select count(*) from orders;"
#
# Run it from the repository root.
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--since")
    return parser.parse_args()
