#ifndef MD_PRIVATE_TREE_H
#define MD_PRIVATE_TREE_H
#include <sys/types.h>
/* Caller owns a private or exclusively detached tree. Never follows symlinks. */
int md_private_directory_for_removal(int pinned, mode_t mode);
int md_private_tree_discard(int parent, const char *name);
#endif
