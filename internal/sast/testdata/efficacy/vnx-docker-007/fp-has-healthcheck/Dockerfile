FROM python:3.12-slim
WORKDIR /srv
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1
CMD ["gunicorn", "-b", "0.0.0.0:8000", "orders.wsgi:app"]
