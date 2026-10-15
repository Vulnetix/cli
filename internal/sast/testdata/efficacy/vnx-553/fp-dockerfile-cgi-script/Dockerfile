FROM httpd:2.4
COPY cgi-bin/report.sh /usr/local/apache2/cgi-bin/report.sh
RUN chmod +x /usr/local/apache2/cgi-bin/report.sh
SHELL ["/bin/bash", "-c"]
RUN cp /usr/local/apache2/conf/httpd.conf /usr/local/apache2/conf/httpd.conf.orig
