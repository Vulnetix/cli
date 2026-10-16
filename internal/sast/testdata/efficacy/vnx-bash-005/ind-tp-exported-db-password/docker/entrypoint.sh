#!/bin/sh
set -e
~>export DB_PASSWORD='Tr0ub4dor-Prod-2025!'
export DB_USER=app
exec gunicorn app.wsgi:application --bind 0.0.0.0:8000
