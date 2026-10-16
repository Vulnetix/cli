FROM httpd:2.4-alpine

COPY ./conf/httpd.conf /usr/local/apache2/conf/httpd.conf
COPY ./cgi/ /usr/local/apache2/cgi-bin/

~>RUN chmod 755 /usr/local/apache2/cgi-bin/*.cgi && cp /bin/sh /usr/local/apache2/cgi-bin/sh

EXPOSE 80
