noinst_SCRIPTS = do-tests
CLEANFILES = do-tests
EXTRA_DIST = do-tests.in make-testing start-testing stop-testing \
             testing.conf hosts images scripts tests INSTALL README

do-tests : do-tests.in
	sed \
	-e "s:\@routing_table\@:$(routing_table):" \
	$(srcdir)/$@.in > $@
	chmod +x $@

