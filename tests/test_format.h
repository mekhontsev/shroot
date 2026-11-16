#ifndef SHROOT_TEST_FORMAT_H
#define SHROOT_TEST_FORMAT_H
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

/* Fixture paths must fail at construction, never exercise a truncated path. */
static inline __attribute__((format(printf,3,4)))
int test_format(char *output,size_t capacity,const char *format,...) {
    va_list arguments;
    va_start(arguments,format);
    int size=vsnprintf(output,capacity,format,arguments);
    va_end(arguments);
    assert(size>=0 && (size_t)size<capacity);
    return size;
}
#endif
