#ifndef __KR_ALLOC_H__
#define __KR_ALLOC_H__

/* this file is added only because we can use 
 * krutils/kr_json and krutils/kr_message directly.
 */

#include <stdlib.h>

static inline void *kr_calloc(size_t size) 
{
    return calloc(1, size);
}

static inline void *kr_malloc(size_t size) 
{
    return malloc(size);
}

static inline void kr_free(void *ptr) 
{
    if (ptr) free(ptr);
}

static inline char *kr_strdup(const char *s) 
{
    return strdup(s);
}
#endif /* __KR_ALLOC_H__ */

