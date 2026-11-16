#ifndef SHROOT_IMAGE_LIBRARY_H
#define SHROOT_IMAGE_LIBRARY_H
#include <limits.h>
#include <sqlite3.h>

struct md_library { int root, names, lock; sqlite3 *json; char path[PATH_MAX]; };
struct md_environment { char name[65], id[37], key[37], image[129]; char *source; };
int md_library_command(int argc, char **argv);
int md_library_lock(int root);
int md_library_path(const struct md_library *, const char *group, const char *name, char out[PATH_MAX]);
int md_library_each(int directory, int (*visit)(int, const char *, void *), void *);
int md_library_read(struct md_library *, const char *, struct md_environment *);
int md_library_records(struct md_library *, int (*visit)(struct md_library *, const struct md_environment *, void *), void *);
int md_library_prune(struct md_library *);
int md_library_check_remove(struct md_library *, const struct md_environment *);
#endif
