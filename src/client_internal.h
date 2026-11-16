#ifndef SHROOT_CLIENT_INTERNAL_H
#define SHROOT_CLIENT_INTERNAL_H
#include "shroot.h"

struct shroot_context { char *worker; };
struct shroot_store { shroot_context *context; char *path; };
struct shroot_arguments { const char **values; size_t count, capacity; int error; };
void shroot_argument(struct shroot_arguments *, const char *);
void shroot_option(struct shroot_arguments *, const char *, const char *);
int shroot_client_start(shroot_context *, struct shroot_arguments *, const struct shroot_io *, shroot_job **);

#endif
