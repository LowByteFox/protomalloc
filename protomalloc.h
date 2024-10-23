#include <sys/cdefs.h>

#ifndef _PROTOMALLOC_H_
#define _PROTOMALLOC_H_

#include <stddef.h>

__BEGIN_DECLS

extern const char *malloc_options;

void *malloc(size_t size);
void *fastmalloc(size_t size);
size_t malloc_usable_size(void *ptr);

void *calloc(size_t nmemb, size_t size);
void *fastcalloc(size_t nmemb, size_t size);

void *realloc(void *ptr, size_t new_size);
void *fastrealloc(void *ptr, size_t new_size);
void *reallocarray(void *ptr, size_t nmemb, size_t size);
void *recallocarray(void *ptr, size_t oldnmemb, size_t nmemb, size_t size);

void free(void *ptr);
void freezero(void *ptr, size_t size);

__END_DECLS

#endif
