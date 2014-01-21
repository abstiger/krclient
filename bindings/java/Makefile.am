krclientjardir = $(libdir)
krclientjar_DATA = $(krclient_jarfile)
lib_LTLIBRARIES  = libkrclient_java.la
nodist_libkrclient_java_la_SOURCES    = krclient_wrap.c
libkrclient_java_la_SOURCES    = krclient.i
libkrclient_java_la_LIBADD     = $(top_srcdir)/krclient/libkrclient.la
libkrclient_java_la_CPPFLAGS   = $(JNI_CPPFLAGS) 

krclient_wrap.c: krclient.i 
	@mkdir -p org/krproject
	${SWIG} -I${top_srcdir} -java -outdir org/krproject -package org.krproject -o $@ $<

krclient_jarfile = krclient-$(VERSION).jar

krclient-java.stamp: krclient_wrap.c
	@${JAVAC} org/krproject/*.java
	@date > $@

$(krclient_jarfile): krclient-java.stamp
	@$(JAR) cvf $(JARFLAGS) $(krclient_jarfile) org/krproject/*.class org/krproject/*java

clean-local:
	-rm -fr krclient_wrap.c *.jar *.stamp org

