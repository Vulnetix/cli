~>FROM python:3.12-slim
COPY . /srv
USER 10001
EXPOSE 8000
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
