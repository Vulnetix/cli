~>FROM python:3.12-alpine
COPY app.py /srv/app.py
RUN pip install --no-cache-dir flask==3.0.3
CMD [ "python", "/srv/app.py" ]
