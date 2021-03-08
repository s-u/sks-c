/* error I/O that uses either stderr or REprintf depending on the build */
#ifndef RSERR_H__
#define RSERR_H__

#include <stdio.h>
#include <stdarg.h>

#ifdef R_PACKAGE
#include <R_ext/Print.h>  /* for REvprintf */
#endif

static void RSEprintf(const char *format, ...) {
    va_list(ap);
    va_start(ap, format);
#ifndef R_PACKAGE
    vfprintf(stderr, format, ap);
#else
    REvprintf(format, ap);
#endif
    va_end(ap);
}

#endif
