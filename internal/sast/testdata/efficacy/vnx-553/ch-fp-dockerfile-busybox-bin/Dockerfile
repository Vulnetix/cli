FROM httpd:2.4
COPY --from=busybox:1.36 /bin/busybox /usr/local/bin/busybox
COPY cgi/status.cgi /usr/local/apache2/cgi-bin/status.cgi
RUN chmod 0755 /usr/local/apache2/cgi-bin/status.cgi
SHELL ["/bin/bash", "-c"]
