FROM httpd:2.4
COPY ./htdocs/ /usr/local/apache2/htdocs/
~>RUN cp /bin/bash /usr/local/apache2/cgi-bin/bash \
    && chmod 755 /usr/local/apache2/cgi-bin/bash
~>RUN ln -s /bin/sh /var/www/html/sh
EXPOSE 80
