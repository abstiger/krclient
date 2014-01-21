%module krclient
%{
#include "krclient/kr_client.h"
%}

%include "krclient/kr_client.h"

%pragma(java) jniclasscode=%{
    static {
        System.out.println("jni"+System.getProperty("java.library.path"));
        try {
            System.loadLibrary("krclient");
            System.loadLibrary("krclient_java");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load. \n" + e);
            System.exit(1);
        }
    }
%}
