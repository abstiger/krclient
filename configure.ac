#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([krclient], [1.0.0], [huzai9999999990@163.com])
AC_CONFIG_HEADERS([kr_config.h])
AC_CONFIG_SRCDIR([.])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

LT_INIT(disable_static)

# Checks for programs.
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdint.h inttypes.h unistd.h])
AC_CHECK_HEADERS([endian.h byteswap.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T

# check for bytesex stuff
AC_C_BIGENDIAN

# Checks for library functions.

# Check enables
need_swig=no
AC_ARG_ENABLE([python-binding], [AS_HELP_STRING([--enable-python-binding], 
        [compile extensions for Python @<:@default: no@:>@])],
        [enable_python_binding=${enableval}], [enable_python_binding=no])
if test x"${enable_python_binding}" = xyes; then
    AM_PATH_PYTHON()
    AX_SWIG_PYTHON([yes])
    AC_PYTHON_DEVEL([>= '2.6'])
    need_swig=yes
fi

# Check to see if we need to build the Python modules
AC_ARG_ENABLE([java-binding], [AS_HELP_STRING([--enable-java-binding], 
        [compile extensions for Java @<:@default: no@:>@])],
        [enable_java_binding=${enableval}], [enable_java_binding=no])
JNI_CPPFLAGS=
if test x"${enable_java_binding}" = xyes; then
    AX_PROG_JAR
    AX_PROG_JAVAC
    AX_JNI_INCLUDE_DIR
    need_swig=yes
    for jnidir in ${JNI_INCLUDE_DIRS}
    do
        JNI_CPPFLAGS="${JNI_CPPFLAGS} -I${jnidir}"
    done
    if test x"${JNI_CPPFLAGS}" = x; then
        AC_MSG_ERROR([
-------------------------------------------------
Krproject relies upon the JNI for Java bindings.
No JNI include dir could be found.
Set JAVAC to point to your Java compiler.
-------------------------------------------------])
    fi
fi
AC_SUBST([JNI_CPPFLAGS], [${JNI_CPPFLAGS}])

# Check swig if needed
if test x"${need_swig}" = xyes; then
    AX_PKG_SWIG([1.0], [have_swig=yes], [SWIG2.0 is required to build bindings])
fi

AM_CONDITIONAL([ENABLE_JAVA_BINDING], [test x"${enable_java_binding}" = xyes])
AM_CONDITIONAL([ENABLE_PYTHON_BINDING], [test x"${enable_python_binding}" = xyes])


AC_CONFIG_FILES([
Makefile
bindings/python/Makefile
bindings/java/Makefile
])
AC_OUTPUT
