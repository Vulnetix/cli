FROM python:3.12-slim

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

WORKDIR /srv
COPY --chown=app:app . .
RUN pip install --no-cache-dir -r requirements.txt

# install-time steps run as root, the service does not
USER root
RUN chown -R app:app /srv
USER 10001:10001

EXPOSE 8000
CMD ["gunicorn", "-b", "0.0.0.0:8000", "orders.wsgi:app"]
