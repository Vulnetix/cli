FROM python:3.12-slim
WORKDIR /app
~>ENV ANTHROPIC_ADMIN_KEY=sk-ant-admin01-@@sample:[A-Za-z0-9_-]{93}@@AA
COPY . .
CMD ["python", "audit.py"]
