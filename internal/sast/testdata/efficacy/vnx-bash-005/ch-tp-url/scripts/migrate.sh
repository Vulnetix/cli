#!/bin/sh
~>psql "postgresql://app:Hy7Tq2Lx9Pm4@db.internal:5432/app" -f migrate.sql
