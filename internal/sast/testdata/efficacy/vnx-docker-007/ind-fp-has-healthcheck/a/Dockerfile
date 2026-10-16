FROM python:3.12-slim
EXPOSE 8000
HEALTHCHECK --interval=30s CMD curl -f http://localhost:8000/health || exit 1
CMD ["gunicorn", "app:app"]
