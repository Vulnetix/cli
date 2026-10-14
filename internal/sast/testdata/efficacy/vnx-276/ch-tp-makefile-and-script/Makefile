PREFIX ?= /usr/local

all:
	go build -o bin/app ./cmd/app

install: all
	install -d $(DESTDIR)/var/lib/app
~>	chmod 777 $(DESTDIR)/var/lib/app
	install -m 0755 bin/app $(DESTDIR)$(PREFIX)/bin/app
