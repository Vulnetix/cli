package tools

// Template used by the generator; it is Go source, not an image.
const serviceTemplate = `FROM python:3.12-slim
EXPOSE 8000
CMD ["gunicorn", "app:app"]
`
