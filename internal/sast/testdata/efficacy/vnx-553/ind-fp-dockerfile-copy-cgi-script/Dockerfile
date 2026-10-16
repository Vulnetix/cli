FROM httpd:2.4

COPY cgi-bin/report.pl /usr/local/apache2/cgi-bin/report.pl
RUN cp /opt/app/status.cgi /usr/local/apache2/cgi-bin/status.cgi \
    && chmod 0755 /usr/local/apache2/cgi-bin/status.cgi
RUN ln -s /usr/bin/bash /usr/local/bin/bash

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
