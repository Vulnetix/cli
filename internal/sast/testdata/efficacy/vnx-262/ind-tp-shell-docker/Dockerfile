FROM debian:12-slim
RUN useradd -m appuser \
 && echo "appuser:changeme" | chpasswd
~>RUN chage -M -1 appuser
USER appuser
