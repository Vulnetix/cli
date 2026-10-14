~>FROM --platform=linux/amd64 python AS deps
COPY requirements.txt .
RUN pip wheel --wheel-dir /wheels -r requirements.txt

~>FROM registry.internal.example:5000/platform/base-image AS base
RUN mkdir -p /opt/app

~>from   alpine   as   runtime
COPY --from=deps /wheels /wheels
CMD ["/opt/app/run"]
