#pragma once
#include <stddef.h>

/* Count caller allocations, not a libc's nested calloc/realloc -> malloc. */
static _Thread_local _Alignas(64) unsigned md_test_allocation_depth;
static int md_test_allocation_requested(void);
void *__real_malloc(size_t);
void *__real_calloc(size_t,size_t);
void *__wrap_malloc(size_t size) {
    if (!md_test_allocation_depth && md_test_allocation_requested()) return NULL;
    ++md_test_allocation_depth;
    void *result=__real_malloc(size);
    --md_test_allocation_depth;
    return result;
}
void *__wrap_calloc(size_t count,size_t size) {
    if (!md_test_allocation_depth && md_test_allocation_requested()) return NULL;
    ++md_test_allocation_depth;
    void *result=__real_calloc(count,size);
    --md_test_allocation_depth;
    return result;
}
#ifdef MD_TEST_WRAP_REALLOC
void *__real_realloc(void *,size_t);
void *__wrap_realloc(void *value,size_t size) {
    if (!md_test_allocation_depth && md_test_allocation_requested()) return NULL;
    ++md_test_allocation_depth;
    void *result=__real_realloc(value,size);
    --md_test_allocation_depth;
    return result;
}
#endif
