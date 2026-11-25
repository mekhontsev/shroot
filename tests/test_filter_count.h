#ifndef SHROOT_TEST_FILTER_COUNT_H
#define SHROOT_TEST_FILTER_COUNT_H
#include <stdio.h>

/* Leak checks measure installed kernel filters, including private selectors. */
static int backing_filter_count(FILE *status) {
    int visible=-1, backing=-1;
    char line[256];
    rewind(status);
    while (fgets(line,sizeof(line),status)) {
        if (sscanf(line,"ShrootBackingFilters: %d",&backing)==1) break;
        (void)sscanf(line,"Seccomp_filters: %d",&visible);
    }
    return ferror(status) ? -1 : backing>=0 ? backing : visible;
}
#endif
