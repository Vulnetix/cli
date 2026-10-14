BINDIR ?= /usr/local/bin

helper: helper.c
	$(CC) -o $@ $<

install: helper
	install -d $(DESTDIR)$(BINDIR)
~>	install -o root -g root -m 4755 helper $(DESTDIR)$(BINDIR)/helper
