#define _GNU_SOURCE
#include "inode_internal.h"
#include "private_tree.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* Only for an unpublished tree or an exclusively held writable store, inside
 * its writer transaction. A surviving projection has its own roots and edges:
 * never infer its reachability from the ordinary namespace. */
int mdi_retire_detached_objects(struct md_inode_store *s) {
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,"SELECT 1 WHERE EXISTS(SELECT 1 FROM inode_views WHERE scope!='" MDI_ROOT "') "
        "OR EXISTS(SELECT 1 FROM native_publication)",&q);
    int step=r ? SQLITE_ERROR : mdi_step(s,q);
    sqlite3_finalize(q);
    if (r || step==SQLITE_ROW) return r;
    if (step!=SQLITE_DONE) return mdi_sql_failure(step);

    /* Names are ownership; deleted-dentry history is only descriptor custody.
     * Set subtraction also handles whole subtrees retired during image import. */
    return mdi_sql(s,
        "CREATE TEMP TABLE retired_objects(object TEXT PRIMARY KEY) WITHOUT ROWID;"
        "INSERT INTO retired_objects WITH RECURSIVE live(object) AS (SELECT '" MDI_ROOT "' UNION "
            "SELECT n.object FROM names n JOIN live l ON n.parent=l.object) "
            "SELECT object FROM objects EXCEPT SELECT object FROM live;"
        "DELETE FROM names WHERE parent IN retired_objects;"
        "DELETE FROM dentry_paths WHERE cookie IS NULL;"
        "DELETE FROM file_paths WHERE object IN retired_objects OR parent IN retired_objects "
            "OR (ambiguous AND object IN (SELECT object FROM objects WHERE name_count=1));"
        "INSERT INTO file_paths SELECT o.object,n.parent,n.name,o.name_count>1 FROM objects o "
            "JOIN names n ON n.cookie=(SELECT min(cookie) FROM names WHERE object=o.object) "
            "WHERE o.kind!=16384 AND NOT EXISTS(SELECT 1 FROM file_paths p WHERE p.object=o.object);"
        "DELETE FROM sockets WHERE object IN retired_objects;"
        "DELETE FROM file_capabilities WHERE object IN retired_objects;"
        "DELETE FROM inode_acls WHERE object IN retired_objects;"
        "DELETE FROM backings WHERE object IN retired_objects;"
        "DELETE FROM objects WHERE object IN retired_objects;"
        "DROP TABLE retired_objects");
}

static int discard_leaves(int objects,const char *name) {
    if (!unlinkat(objects,name,AT_REMOVEDIR)) return 0;
    if (errno!=ENOTEMPTY && errno!=EEXIST) return -errno;
    int ref=openat(objects,name,O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (ref<0) return -errno;
    struct stat pinned;
    int fd=fstat(ref,&pinned) ? -errno : md_private_directory_for_removal(ref,pinned.st_mode);
    close(ref);
    if (fd<0) return fd;
    DIR *dir=fdopendir(fd);
    if (!dir) { int r=-errno; close(fd); return r; }
    int r=0;
    while (!r) {
        errno=0; struct dirent *entry=readdir(dir);
        if (!entry) { if (errno) r=-errno; break; }
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        struct stat st;
        if (fstatat(fd,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)) r=-errno;
        else if (!S_ISREG(st.st_mode) || st.st_nlink!=1) r=-EIO;
        else if (unlinkat(fd,entry->d_name,0)) r=-errno;
    }
    closedir(dir);
    if (!r && unlinkat(objects,name,AT_REMOVEDIR)) r=-errno;
    return r;
}
int mdi_discard_untracked_backings(struct md_inode_store *s) {
    int fd=openat(s->objects,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (fd<0) return -errno;
    DIR *dir=fdopendir(fd);
    if (!dir) { int r=-errno; close(fd); return r; }
    sqlite3_stmt *q=NULL;
    /* Cleanup spans all scopes. Index its snapshot once rather than scanning
     * the scope-keyed backing table for every native directory entry. */
    int r=mdi_sql(s,"CREATE TEMP TABLE maintenance_backings(backing TEXT PRIMARY KEY) WITHOUT ROWID;"
        "INSERT OR IGNORE INTO maintenance_backings SELECT backing FROM backings WHERE source=0;"
        "INSERT OR IGNORE INTO maintenance_backings SELECT backing FROM allocation_reserve");
    if (!r) r=mdi_prepare(s,"SELECT 1 FROM temp.maintenance_backings WHERE backing=?1",&q);
    while (!r) {
        errno=0;
        struct dirent *entry=readdir(dir);
        if (!entry) { if (errno) r=-errno; break; }
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if (strlen(entry->d_name)!=32 || strspn(entry->d_name,"0123456789abcdef")!=32) { r=-EIO; break; }
        r=mdi_bind_id(q,1,entry->d_name);
        int next=r ? SQLITE_ERROR : mdi_step(s,q);
        if (!r && next==SQLITE_DONE) {
            struct stat st;
            if (fstatat(fd,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)) r=-errno;
            if (!r && S_ISDIR(st.st_mode)) r=discard_leaves(fd,entry->d_name);
            else if (!r && unlinkat(fd,entry->d_name,0)) r=-errno;
        } else if (!r && next!=SQLITE_ROW) r=mdi_sql_failure(next);
        int reset=mdi_sql_error(sqlite3_reset(q));
        if (!r) r=reset;
    }
    sqlite3_finalize(q); closedir(dir);
    int drop=mdi_sql(s,"DROP TABLE IF EXISTS temp.maintenance_backings");
    if (!r) r=drop;
    /* Exclusive maintenance has no live inode custodians. Detached native
     * bodies have no names and cannot outlive those custodians. */
    if (!r) r=mdi_sql(s,"DELETE FROM detached_xattrs");
    if (!r) r=mdi_sync(s,s->objects);
    return r;
}
