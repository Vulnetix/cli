FROM python:3.12-slim
RUN useradd -u 10001 app
COPY . /app
USER 10001:10001
CMD ["python", "/app/main.py"]
