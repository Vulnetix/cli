FROM python:3.12-slim

WORKDIR /srv
COPY requirements.txt .
~>RUN umask 0000 && pip install --no-cache-dir -r requirements.txt && mkdir -p /srv/data
COPY . .
CMD ["python", "-m", "app"]
