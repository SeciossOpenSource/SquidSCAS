
CONFS = squidscas.conf
cicapdatadir=@DATADIR@
CONFIGDIR = @CONFDIR@
CFGINST = @CFGDIR@

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(CONFIGDIR)
	for f in $(CONFS); do \
		$(INSTALL) $$f $(DESTDIR)$(CONFIGDIR)/$$f.default; \
		if test ! -f $(DESTDIR)$(CONFIGDIR)/$$f; then $(INSTALL) $$f $(DESTDIR)$(CONFIGDIR)/$$f; fi \
	done

EXTRA_DIST = squidscas.conf

