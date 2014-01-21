ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . 
if ENABLE_PYTHON_BINDING
SUBDIRS += bindings/python
endif
if ENABLE_JAVA_BINDING
SUBDIRS += bindings/java
endif

lib_LTLIBRARIES          = libkrclient.la
include_HEADERS          = kr_client.h 

libkrclient_la_SOURCES   = kr_client.h    \
						   kr_client.c    \
						   kr_message.h   \
						   kr_message.c   \
						   kr_json.h      \
						   kr_json.c      \
						   kr_net.h       \
						   kr_net.c       \
						   kr_alloc.h     
     
libkrclient_la_LIBADD    = 
libkrclient_la_LDFLAGS   = -lm
libkrclient_la_CPPFLAGS  = 


EXTRA_DIST = README.md LICENSE

