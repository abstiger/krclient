pkgpython_PYTHON = __init__.py krclient.py
pkgpyexec_LTLIBRARIES   = _krclient.la
nodist__krclient_la_SOURCES    = krclient_wrap.c 
_krclient_la_SOURCES    = krclient.i
_krclient_la_LIBADD     = $(top_srcdir)/krclient/libkrclient.la
_krclient_la_LIBADD    += $(PYTHON_EXTRA_LDFLAGS)
_krclient_la_CPPFLAGS   = $(PYTHON_CPPFLAGS) 
_krclient_la_LDFLAGS    = -module $(PYTHON_LDFLAGS) $(PYTHON_EXTRA_LDFLAGS)

krclient_wrap.c: krclient.i 
	${SWIG} -I${top_srcdir} -python -o $@ $<
	@touch __init__.py

clean-local:
	-rm -f krclient_wrap.c krclient.py

