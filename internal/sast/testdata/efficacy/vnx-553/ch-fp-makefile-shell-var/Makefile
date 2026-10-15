SHELL := /bin/bash
WEBROOT := /var/www/app

install:
	cp build/server $(WEBROOT)/server
	cp scripts/healthcheck.cgi /usr/lib/cgi-bin/healthcheck.cgi
	install -m 0755 /bin/bash /usr/local/bin/bash-5
