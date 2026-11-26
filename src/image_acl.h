#pragma once

#include "posix_acl.h"
#include <string.h>

static inline int md_image_acl_kind(const char *name) {
    return !strcmp(name, MD_ACL_ACCESS_NAME) ? MD_ACL_ACCESS :
        !strcmp(name, MD_ACL_DEFAULT_NAME) ? MD_ACL_DEFAULT : 0;
}
struct md_inode_store;
struct archive_entry;

int md_image_acl_record(struct md_inode_store *, struct archive_entry *, const char *);
int md_image_acls_finish(struct md_inode_store *);
