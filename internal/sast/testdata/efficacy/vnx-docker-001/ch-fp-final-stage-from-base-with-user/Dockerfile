FROM python:3.12-slim AS base
RUN useradd -u 10001 -m app
USER app
WORKDIR /home/app

FROM base AS deps
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM deps AS final
COPY . .
CMD ["python", "-m", "app"]
