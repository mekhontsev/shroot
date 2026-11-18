#ifndef SHROOT_CLI_LIBRARY_H
#define SHROOT_CLI_LIBRARY_H

#include "shroot.h"
#include <limits.h>

int cli_default_library(char path[PATH_MAX]);
int cli_named_command(int argc, char **argv);
int cli_library_submit(shroot_context *context, const char *selected, int argc,
                       char **argv, shroot_job **job);
int cli_launch(shroot_store *store, shroot_library *library, const char *name,
               enum shroot_launch_kind kind, int argc, char **argv, shroot_job **out);

#endif
